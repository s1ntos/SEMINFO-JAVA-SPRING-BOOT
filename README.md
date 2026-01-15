# 🔒 Guia de Resolução de Vulnerabilidades - Sistema de Autenticação

Este documento fornece instruções passo a passo para resolver todas as vulnerabilidades identificadas no sistema de autenticação, ordenadas por prioridade (Crítica → Média → Baixa).

---

## 🔴 VULNERABILIDADES CRÍTICAS

### 1. Armazenamento de Token em localStorage (Vulnerável a XSS)

#### Problema
Tokens armazenados em `localStorage` podem ser roubados via XSS (Cross-Site Scripting).

#### Solução: Implementar Refresh Tokens com HttpOnly Cookies

**PASSO 1: Backend - Atualizar JwtTokenProvider**

```java
// src/main/java/com/teste/backendzenix/shared/security/JwtTokenProvider.java

@Component
public class JwtTokenProvider {
    
    @Value("${jwt.secret}")
    private String secret;
    
    @Value("${jwt.access.expiration:900000}") // 15 minutos
    private long accessTokenExpirationMs;
    
    @Value("${jwt.refresh.expiration:604800000}") // 7 dias
    private long refreshTokenExpirationMs;
    
    // Gerar Access Token (curto)
    public String generateAccessToken(String email, UUID userId) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("userId", userId.toString());
        claims.put("type", "access");
        
        return Jwts.builder()
                .claims(claims)
                .subject(email)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + accessTokenExpirationMs))
                .signWith(getSigningKey(), Jwts.SIG.HS256)
                .compact();
    }
    
    // Gerar Refresh Token (longo)
    public String generateRefreshToken(String email, UUID userId) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("userId", userId.toString());
        claims.put("type", "refresh");
        
        return Jwts.builder()
                .claims(claims)
                .subject(email)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + refreshTokenExpirationMs))
                .signWith(getSigningKey(), Jwts.SIG.HS256)
                .compact();
    }
    
    // Validar tipo de token
    public boolean isRefreshToken(String token) {
        try {
            Claims claims = getValidClaims(token);
            return "refresh".equals(claims.get("type"));
        } catch (Exception e) {
            return false;
        }
    }
}
```

**PASSO 2: Backend - Criar RefreshToken Entity**

```java
// src/main/java/com/teste/backendzenix/auth/entity/RefreshToken.java

@Entity
@Table(name = "refresh_tokens")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class RefreshToken {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;
    
    @Column(nullable = false, unique = true)
    private String token;
    
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;
    
    @Column(nullable = false)
    private LocalDateTime expiresAt;
    
    @Column(nullable = false)
    private LocalDateTime createdAt;
    
    @Column
    private LocalDateTime revokedAt;
    
    public boolean isExpired() {
        return expiresAt.isBefore(LocalDateTime.now());
    }
    
    public boolean isRevoked() {
        return revokedAt != null;
    }
}
```

**PASSO 3: Backend - Criar RefreshTokenRepository**

```java
// src/main/java/com/teste/backendzenix/auth/repository/RefreshTokenRepository.java

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {
    Optional<RefreshToken> findByToken(String token);
    void deleteByUser(User user);
    void deleteByExpiresAtBefore(LocalDateTime now);
}
```

**PASSO 4: Backend - Atualizar AuthService**

```java
// src/main/java/com/teste/backendzenix/auth/service/AuthService.java

@Transactional
public AuthResponse login(LoginRequest request) {
    // ... validação existente ...
    
    User user = userRepository.findByEmail(request.getEmail())
            .orElseThrow(() -> new RuntimeException("Credenciais inválidas"));
    
    if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
        throw new RuntimeException("Credenciais inválidas");
    }
    
    String accessToken = jwtTokenProvider.generateAccessToken(user.getEmail(), user.getId());
    String refreshToken = jwtTokenProvider.generateRefreshToken(user.getEmail(), user.getId());
    
    // Salvar refresh token no banco
    RefreshToken refreshTokenEntity = new RefreshToken();
    refreshTokenEntity.setToken(refreshToken);
    refreshTokenEntity.setUser(user);
    refreshTokenEntity.setCreatedAt(LocalDateTime.now());
    refreshTokenEntity.setExpiresAt(LocalDateTime.now().plusDays(7));
    refreshTokenRepository.save(refreshTokenEntity);
    
    AuthResponse response = new AuthResponse();
    response.setAccessToken(accessToken);
    response.setRefreshToken(refreshToken); // Será enviado como cookie no próximo passo
    response.setExpiresIn(900); // 15 minutos em segundos
    response.setUser(userToDto(user));
    
    return response;
}
```

**PASSO 5: Backend - Atualizar AuthController para usar Cookies**

```java
// src/main/java/com/teste/backendzenix/auth/controller/AuthController.java

@PostMapping("/login")
public ResponseEntity<AuthResponse> login(
        @Valid @RequestBody LoginRequest request,
        HttpServletResponse response) {
    
    AuthResponse authResponse = authService.login(request);
    
    // Configurar cookie HttpOnly para refresh token
    Cookie refreshTokenCookie = new Cookie("refresh_token", authResponse.getRefreshToken());
    refreshTokenCookie.setHttpOnly(true);
    refreshTokenCookie.setSecure(true); // Apenas HTTPS em produção
    refreshTokenCookie.setPath("/auth");
    refreshTokenCookie.setMaxAge(7 * 24 * 60 * 60); // 7 dias
    refreshTokenCookie.setAttribute("SameSite", "Strict");
    response.addCookie(refreshTokenCookie);
    
    // Não enviar refresh token no body
    authResponse.setRefreshToken(null);
    
    return ResponseEntity.ok(authResponse);
}
```

**PASSO 6: Backend - Criar endpoint de Refresh**

```java
// src/main/java/com/teste/backendzenix/auth/controller/AuthController.java

@PostMapping("/refresh")
public ResponseEntity<AuthResponse> refresh(
        @CookieValue(value = "refresh_token", required = false) String refreshToken,
        HttpServletResponse response) {
    
    if (refreshToken == null) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }
    
    try {
        // Validar refresh token
        RefreshToken tokenEntity = refreshTokenRepository.findByToken(refreshToken)
                .orElseThrow(() -> new RuntimeException("Refresh token inválido"));
        
        if (tokenEntity.isExpired() || tokenEntity.isRevoked()) {
            throw new RuntimeException("Refresh token expirado ou revogado");
        }
        
        User user = tokenEntity.getUser();
        
        // Gerar novo access token
        String newAccessToken = jwtTokenProvider.generateAccessToken(user.getEmail(), user.getId());
        
        // Rotacionar refresh token (opcional, mas recomendado)
        refreshTokenRepository.delete(tokenEntity);
        String newRefreshToken = jwtTokenProvider.generateRefreshToken(user.getEmail(), user.getId());
        
        RefreshToken newTokenEntity = new RefreshToken();
        newTokenEntity.setToken(newRefreshToken);
        newTokenEntity.setUser(user);
        newTokenEntity.setCreatedAt(LocalDateTime.now());
        newTokenEntity.setExpiresAt(LocalDateTime.now().plusDays(7));
        refreshTokenRepository.save(newTokenEntity);
        
        // Atualizar cookie
        Cookie cookie = new Cookie("refresh_token", newRefreshToken);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/auth");
        cookie.setMaxAge(7 * 24 * 60 * 60);
        cookie.setAttribute("SameSite", "Strict");
        response.addCookie(cookie);
        
        AuthResponse authResponse = new AuthResponse();
        authResponse.setAccessToken(newAccessToken);
        authResponse.setExpiresIn(900);
        authResponse.setUser(userToDto(user));
        
        return ResponseEntity.ok(authResponse);
        
    } catch (Exception e) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }
}
```

**PASSO 7: Frontend - Atualizar client.ts**

```typescript
// src/lib/api/client.ts

const API_BASE_URL = getApiBaseUrl();

// Armazenar apenas access token (curto) em memória
let accessToken: string | null = null;

export function setAccessToken(token: string | null) {
  accessToken = token;
}

export function getAccessToken(): string | null {
  return accessToken;
}

export async function apiClient<T>(
  endpoint: string,
  options: RequestOptions = {}
): Promise<{ data: T | null; error: any }> {
  const {
    method = 'GET',
    headers = {},
    body,
    requiresAuth = true,
  } = options;

  try {
    let token = accessToken;
    
    // Se não houver token e for necessário, tentar refresh
    if (requiresAuth && !token && typeof window !== 'undefined') {
      const refreshed = await refreshAccessToken();
      if (refreshed) {
        token = accessToken;
      }
    }

    const requestHeaders: Record<string, string> = {
      'Content-Type': 'application/json',
      ...headers,
    };

    if (token) {
      requestHeaders['Authorization'] = `Bearer ${token}`;
    }

    // ... resto do código ...

    const response = await fetch(`${API_BASE_URL}${endpoint}`, requestOptions);

    // Se 401, tentar refresh e retry
    if (response.status === 401 && requiresAuth) {
      const refreshed = await refreshAccessToken();
      if (refreshed) {
        // Retry com novo token
        requestHeaders['Authorization'] = `Bearer ${accessToken}`;
        const retryResponse = await fetch(`${API_BASE_URL}${endpoint}`, {
          ...requestOptions,
          headers: requestHeaders,
        });
        
        if (!retryResponse.ok) {
          // Se ainda falhar, fazer logout
          await logout();
          window.location.href = '/auth?error=session_expired';
          return { data: null, error: { message: 'Sessão expirada' } };
        }
        
        const data = await retryResponse.json().catch(() => null);
        return { data, error: null };
      } else {
        // Refresh falhou, fazer logout
        await logout();
        window.location.href = '/auth?error=session_expired';
        return { data: null, error: { message: 'Sessão expirada' } };
      }
    }

    // ... resto do tratamento de resposta ...
  } catch (error: any) {
    // ... tratamento de erro ...
  }
}

// Função para refresh do access token
async function refreshAccessToken(): Promise<boolean> {
  try {
    const response = await fetch(`${API_BASE_URL}/auth/refresh`, {
      method: 'POST',
      credentials: 'include', // IMPORTANTE: inclui cookies
    });

    if (response.ok) {
      const data = await response.json();
      setAccessToken(data.accessToken);
      return true;
    }
    return false;
  } catch (error) {
    return false;
  }
}

// Função de logout
export async function logout() {
  accessToken = null;
  // O cookie será removido pelo backend ao fazer logout
  await fetch(`${API_BASE_URL}/auth/logout`, {
    method: 'POST',
    credentials: 'include',
  });
}
```

**PASSO 8: Frontend - Atualizar AuthContext**

```typescript
// src/contexts/AuthContext.tsx

const signIn = async (email: string, password: string) => {
  try {
    // Importar funções do client
    const { post, setAccessToken } = await import('@/lib/api/client');
    
    const response = await fetch(`${API_BASE_URL}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include', // IMPORTANTE: inclui cookies
      body: JSON.stringify({ email, password }),
    });

    if (!response.ok) {
      const error = await response.json();
      return { error };
    }

    const data = await response.json();
    
    // Armazenar apenas access token em memória (não localStorage!)
    setAccessToken(data.accessToken);
    
    // Armazenar dados do usuário em localStorage (não crítico)
    localStorage.setItem('auth_user', JSON.stringify(data.user));
    
    setUser(data.user);
    const userProfile = await fetchProfile();
    setProfile(userProfile);

    return { error: null };
  } catch (error: any) {
    return { error };
  }
};

const signOut = async () => {
  const { logout } = await import('@/lib/api/client');
  await logout();
  localStorage.removeItem('auth_user');
  setUser(null);
  setProfile(null);
};
```

**PASSO 9: Atualizar application.properties**

```properties
# Access Token (curto)
jwt.access.expiration=900000

# Refresh Token (longo)
jwt.refresh.expiration=604800000
```

---

### 2. Falta de Rate Limiting

#### Problema
Sem limitação de tentativas, vulnerável a brute force e DDoS.

#### Solução: Implementar Rate Limiting com Bucket4j

**PASSO 1: Adicionar dependência (pom.xml)**

```xml
<dependency>
    <groupId>com.bucket4j</groupId>
    <artifactId>bucket4j-core</artifactId>
    <version>8.10.1</version>
</dependency>

<dependency>
    <groupId>com.bucket4j</groupId>
    <artifactId>bucket4j-redis</artifactId>
    <version>8.10.1</version>
</dependency>
```

**PASSO 2: Criar RateLimiterService**

```java
// src/main/java/com/teste/backendzenix/shared/service/RateLimiterService.java

@Service
@Slf4j
public class RateLimiterService {
    
    private final Map<String, Bucket> cache = new ConcurrentHashMap<>();
    
    public Bucket resolveBucket(String key, int capacity, int refillTokens, Duration refillDuration) {
        return cache.computeIfAbsent(key, k -> {
            Bandwidth limit = Bandwidth.classic(capacity, Refill.intervally(refillTokens, refillDuration));
            return Bucket4j.builder()
                    .addLimit(limit)
                    .build();
        });
    }
    
    public boolean tryConsume(String key, int capacity, int refillTokens, Duration refillDuration) {
        Bucket bucket = resolveBucket(key, capacity, refillTokens, refillDuration);
        return bucket.tryConsume(1);
    }
}
```

**PASSO 3: Criar RateLimitInterceptor**

```java
// src/main/java/com/teste/backendzenix/shared/interceptor/RateLimitInterceptor.java

@Component
@RequiredArgsConstructor
@Slf4j
public class RateLimitInterceptor implements HandlerInterceptor {
    
    private final RateLimiterService rateLimiterService;
    
    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        String endpoint = request.getRequestURI();
        String ipAddress = getClientIpAddress(request);
        String key = endpoint + ":" + ipAddress;
        
        // Configurações por endpoint
        if (endpoint.contains("/auth/login")) {
            // 5 tentativas por minuto
            if (!rateLimiterService.tryConsume(key, 5, 5, Duration.ofMinutes(1))) {
                log.warn("Rate limit excedido para IP: {} em endpoint: {}", ipAddress, endpoint);
                response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
                response.setContentType("application/json");
                try {
                    response.getWriter().write("{\"error\":\"Muitas tentativas. Tente novamente em alguns minutos.\"}");
                } catch (IOException e) {
                    log.error("Erro ao escrever resposta", e);
                }
                return false;
            }
        } else if (endpoint.contains("/auth/register")) {
            // 3 registros por hora
            if (!rateLimiterService.tryConsume(key, 3, 3, Duration.ofHours(1))) {
                response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
                return false;
            }
        } else if (endpoint.contains("/auth/reset-password")) {
            // 3 tentativas por hora
            if (!rateLimiterService.tryConsume(key, 3, 3, Duration.ofHours(1))) {
                response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
                return false;
            }
        }
        
        return true;
    }
    
    private String getClientIpAddress(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }
        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty()) {
            return xRealIp;
        }
        return request.getRemoteAddr();
    }
}
```

**PASSO 4: Registrar Interceptor**

```java
// src/main/java/com/teste/backendzenix/shared/config/WebConfig.java

@Configuration
@RequiredArgsConstructor
public class WebConfig implements WebMvcConfigurer {
    
    private final RateLimitInterceptor rateLimitInterceptor;
    
    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(rateLimitInterceptor)
                .addPathPatterns("/auth/**");
    }
}
```

---

### 3. Token JWT Sem Refresh Token

**✅ RESOLVIDO** na vulnerabilidade #1 (implementação de refresh tokens).

---

### 4. Senha Mínima Muito Fraca

#### Problema
Senha de 6 caracteres é extremamente fraca.

#### Solução: Implementar Política de Senha Forte

**PASSO 1: Backend - Criar PasswordValidator**

```java
// src/main/java/com/teste/backendzenix/shared/validation/PasswordValidator.java

@Component
public class PasswordValidator {
    
    private static final String PASSWORD_PATTERN = 
        "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,}$";
    
    private static final Pattern pattern = Pattern.compile(PASSWORD_PATTERN);
    
    public ValidationResult validate(String password) {
        ValidationResult result = new ValidationResult();
        
        if (password == null || password.length() < 8) {
            result.addError("Senha deve ter no mínimo 8 caracteres");
        }
        
        if (password != null && password.length() >= 8) {
            if (!pattern.matcher(password).matches()) {
                result.addError("Senha deve conter pelo menos uma letra maiúscula, uma minúscula, um número e um símbolo (@$!%*?&)");
            }
        }
        
        // Verificar senhas comuns (opcional, pode usar API externa)
        if (isCommonPassword(password)) {
            result.addError("Esta senha é muito comum. Escolha uma senha mais segura");
        }
        
        return result;
    }
    
    private boolean isCommonPassword(String password) {
        // Lista de senhas comuns (exemplo simplificado)
        List<String> commonPasswords = Arrays.asList(
            "12345678", "password", "123456789", "1234567",
            "senha123", "Password1", "123456", "qwerty"
        );
        return commonPasswords.contains(password.toLowerCase());
    }
    
    @Data
    @AllArgsConstructor
    @NoArgsConstructor
    public static class ValidationResult {
        private List<String> errors = new ArrayList<>();
        private boolean valid = true;
        
        public void addError(String error) {
            errors.add(error);
            valid = false;
        }
    }
}
```

**PASSO 2: Backend - Atualizar DTOs**

```java
// src/main/java/com/teste/backendzenix/auth/dto/RegisterRequest.java

@Data
public class RegisterRequest {
    @NotBlank(message = "Nome é obrigatório")
    private String nome;
    
    @NotBlank(message = "Email é obrigatório")
    @Email(message = "Email inválido")
    private String email;
    
    @NotBlank(message = "Senha é obrigatória")
    @Size(min = 8, message = "Senha deve ter no mínimo 8 caracteres")
    private String password;
}

// src/main/java/com/teste/backendzenix/auth/dto/UpdatePasswordRequest.java

@Data
public class UpdatePasswordRequest {
    @NotBlank(message = "Senha atual é obrigatória")
    private String currentPassword;
    
    @NotBlank(message = "Nova senha é obrigatória")
    @Size(min = 8, message = "Senha deve ter no mínimo 8 caracteres")
    private String newPassword;
}
```

**PASSO 3: Backend - Atualizar AuthService**

```java
// src/main/java/com/teste/backendzenix/auth/service/AuthService.java

@RequiredArgsConstructor
public class AuthService {
    private final PasswordValidator passwordValidator;
    
    @Transactional
    public AuthResponse register(RegisterRequest request) {
        // Validar senha
        PasswordValidator.ValidationResult validation = passwordValidator.validate(request.getPassword());
        if (!validation.isValid()) {
            throw new RuntimeException(String.join(", ", validation.getErrors()));
        }
        
        // ... resto do código de registro ...
    }
    
    @Transactional
    public void updatePassword(UUID userId, String currentPassword, String newPassword) {
        // Validar nova senha
        PasswordValidator.ValidationResult validation = passwordValidator.validate(newPassword);
        if (!validation.isValid()) {
            throw new RuntimeException(String.join(", ", validation.getErrors()));
        }
        
        // ... resto do código ...
    }
}
```

**PASSO 4: Frontend - Criar passwordValidator.ts**

```typescript
// src/lib/utils/passwordValidator.ts

export interface PasswordValidationResult {
  valid: boolean;
  errors: string[];
}

export function validatePassword(password: string): PasswordValidationResult {
  const errors: string[] = [];
  
  if (!password || password.length < 8) {
    errors.push("Senha deve ter no mínimo 8 caracteres");
  }
  
  if (password && password.length >= 8) {
    if (!/[a-z]/.test(password)) {
      errors.push("Senha deve conter pelo menos uma letra minúscula");
    }
    if (!/[A-Z]/.test(password)) {
      errors.push("Senha deve conter pelo menos uma letra maiúscula");
    }
    if (!/\d/.test(password)) {
      errors.push("Senha deve conter pelo menos um número");
    }
    if (!/[@$!%*?&]/.test(password)) {
      errors.push("Senha deve conter pelo menos um símbolo (@$!%*?&)");
    }
  }
  
  // Verificar senhas comuns
  const commonPasswords = [
    "12345678", "password", "123456789", "1234567",
    "senha123", "Password1", "123456", "qwerty"
  ];
  if (commonPasswords.includes(password.toLowerCase())) {
    errors.push("Esta senha é muito comum. Escolha uma senha mais segura");
  }
  
  return {
    valid: errors.length === 0,
    errors
  };
}
```

**PASSO 5: Frontend - Atualizar componentes de registro/login**

```typescript
// src/app/(public)/auth/page.tsx

import { validatePassword } from '@/lib/utils/passwordValidator';

const handleRegister = async (e: React.FormEvent) => {
  e.preventDefault();
  setError("");
  
  // Validar senha antes de enviar
  const validation = validatePassword(registerPassword);
  if (!validation.valid) {
    setError(validation.errors.join(", "));
    return;
  }
  
  // ... resto do código ...
};
```

---

### 5. Token de Reset no Frontend (URL)

#### Problema
Token exposto na URL pode vazar em logs, histórico, etc.

#### Solução: Usar POST com token no body

**PASSO 1: Backend - Atualizar endpoint**

```java
// O endpoint já está correto (POST /auth/reset-password/confirm)
// Apenas garantir que o token vem no body, não na URL
```

**PASSO 2: Frontend - Atualizar página de reset**

```typescript
// src/app/(public)/auth/reset-password/confirm/page.tsx

// Em vez de pegar token da URL, pegar do email ou código temporário
// OU: Usar POST mesmo com token na URL, mas validar imediatamente e limpar

useEffect(() => {
  const tokenFromUrl = searchParams.get("token");
  if (tokenFromUrl) {
    // Validar token imediatamente via API
    validateResetToken(tokenFromUrl).then(isValid => {
      if (isValid) {
        setToken(tokenFromUrl);
        // Limpar token da URL após salvar
        window.history.replaceState({}, '', window.location.pathname);
      } else {
        setError("Token inválido ou expirado");
        setToken("");
      }
    });
  }
}, []);

async function validateResetToken(token: string): Promise<boolean> {
  try {
    const response = await fetch(`${API_BASE_URL}/auth/reset-password/validate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token }),
    });
    return response.ok;
  } catch {
    return false;
  }
}
```

**PASSO 3: Backend - Criar endpoint de validação**

```java
// src/main/java/com/teste/backendzenix/auth/controller/AuthController.java

@PostMapping("/reset-password/validate")
public ResponseEntity<MessageResponse> validateResetToken(
        @RequestBody Map<String, String> request) {
    String token = request.get("token");
    
    try {
        User user = userRepository.findByResetPasswordToken(token)
                .orElseThrow(() -> new RuntimeException("Token inválido"));
        
        if (user.getResetPasswordTokenExpiry() == null || 
            user.getResetPasswordTokenExpiry().isBefore(LocalDateTime.now())) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(MessageResponse.of("Token expirado"));
        }
        
        return ResponseEntity.ok(MessageResponse.of("Token válido"));
    } catch (Exception e) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(MessageResponse.of("Token inválido"));
    }
}
```

---

### 6. Falta de Verificação de Email

#### Problema
Usuários podem criar contas sem verificar email.

#### Solução: Implementar verificação de email obrigatória

**PASSO 1: Backend - Atualizar User Entity**

```java
// src/main/java/com/teste/backendzenix/auth/entity/User.java

@Entity
@Table(name = "users")
@Data
public class User {
    // ... campos existentes ...
    
    @Column(nullable = false)
    private Boolean emailVerified = false;
    
    @Column
    private String emailVerificationToken;
    
    @Column
    private LocalDateTime emailVerificationTokenExpiry;
}
```

**PASSO 2: Backend - Atualizar AuthService**

```java
// src/main/java/com/teste/backendzenix/auth/service/AuthService.java

@Transactional
public AuthResponse register(RegisterRequest request) {
    // ... validação existente ...
    
    User user = new User();
    // ... preencher campos ...
    
    // Gerar token de verificação
    String verificationToken = generateVerificationToken();
    user.setEmailVerificationToken(verificationToken);
    user.setEmailVerificationTokenExpiry(LocalDateTime.now().plusHours(24));
    user.setEmailVerified(false);
    
    userRepository.save(user);
    
    // Enviar email de verificação
    String verificationLink = appUrl + "/auth/verify-email?token=" + verificationToken;
    emailService.sendVerificationEmail(user.getEmail(), user.getNome(), verificationLink);
    
    // NÃO retornar token de autenticação ainda
    throw new RuntimeException("Email de verificação enviado. Verifique sua caixa de entrada.");
}

@Transactional
public void verifyEmail(String token) {
    User user = userRepository.findByEmailVerificationToken(token)
            .orElseThrow(() -> new RuntimeException("Token de verificação inválido"));
    
    if (user.getEmailVerificationTokenExpiry() == null || 
        user.getEmailVerificationTokenExpiry().isBefore(LocalDateTime.now())) {
        throw new RuntimeException("Token de verificação expirado");
    }
    
    user.setEmailVerified(true);
    user.setEmailVerificationToken(null);
    user.setEmailVerificationTokenExpiry(null);
    userRepository.save(user);
}

// No login, verificar se email está verificado
@Transactional
public AuthResponse login(LoginRequest request) {
    User user = userRepository.findByEmail(request.getEmail())
            .orElseThrow(() -> new RuntimeException("Credenciais inválidas"));
    
    if (!user.getEmailVerified()) {
        throw new RuntimeException("Email não verificado. Verifique sua caixa de entrada.");
    }
    
    // ... resto do código de login ...
}
```

**PASSO 3: Backend - Criar endpoint de verificação**

```java
// src/main/java/com/teste/backendzenix/auth/controller/AuthController.java

@PostMapping("/verify-email")
public ResponseEntity<MessageResponse> verifyEmail(@RequestParam String token) {
    authService.verifyEmail(token);
    return ResponseEntity.ok(MessageResponse.of("Email verificado com sucesso"));
}

@PostMapping("/resend-verification")
public ResponseEntity<MessageResponse> resendVerification(@RequestBody ResetPasswordRequest request) {
    authService.resendVerificationEmail(request.getEmail());
    return ResponseEntity.ok(MessageResponse.of("Email de verificação reenviado"));
}
```

**PASSO 4: Frontend - Criar página de verificação**

```typescript
// src/app/(public)/auth/verify-email/page.tsx

'use client';

import { useEffect, useState } from 'react';
import { useSearchParams, useRouter } from 'next/navigation';

export default function VerifyEmailPage() {
  const searchParams = useSearchParams();
  const router = useRouter();
  const [status, setStatus] = useState<'loading' | 'success' | 'error'>('loading');
  
  useEffect(() => {
    const token = searchParams.get('token');
    if (!token) {
      setStatus('error');
      return;
    }
    
    verifyEmail(token);
  }, []);
  
  async function verifyEmail(token: string) {
    try {
      const response = await fetch(`${API_BASE_URL}/auth/verify-email?token=${token}`, {
        method: 'POST',
      });
      
      if (response.ok) {
        setStatus('success');
        setTimeout(() => router.push('/auth'), 3000);
      } else {
        setStatus('error');
      }
    } catch (error) {
      setStatus('error');
    }
  }
  
  // ... renderizar UI ...
}
```

---

### 7. Google Client ID/Secret Expostos

#### Problema
Credenciais hardcoded no código.

#### Solução: Usar apenas variáveis de ambiente

**PASSO 1: Remover do código**

```java
// ❌ REMOVER estas linhas de application.properties:
// spring.security.oauth2.client.registration.google.client-id=...
// spring.security.oauth2.client.registration.google.client-secret=...

// ✅ Manter apenas:
spring.security.oauth2.client.registration.google.client-id=${GOOGLE_CLIENT_ID}
spring.security.oauth2.client.registration.google.client-secret=${GOOGLE_CLIENT_SECRET}
```

**PASSO 2: Configurar variáveis de ambiente**

```bash
# .env (nunca commitar!)
GOOGLE_CLIENT_ID=sua_client_id_aqui
GOOGLE_CLIENT_SECRET=sua_client_secret_aqui

# docker-compose.yaml (usar secrets)
services:
  app:
    environment:
      GOOGLE_CLIENT_ID: ${GOOGLE_CLIENT_ID}
      GOOGLE_CLIENT_SECRET: ${GOOGLE_CLIENT_SECRET}
```

**PASSO 3: Atualizar .gitignore**

```gitignore
# .gitignore
.env
.env.local
.env.production
*.env
application.properties  # Não commitar arquivo com credenciais reais
```

---

## 🟡 VULNERABILIDADES MÉDIAS

### 8. Falta de 2FA

**Implementação completa requer biblioteca TOTP. Exemplo básico:**

```java
// Adicionar dependência (Google Authenticator)
<dependency>
    <groupId>dev.samstevens.totp</groupId>
    <artifactId>totp</artifactId>
    <version>1.7.1</version>
</dependency>

// Criar campo no User
private String twoFactorSecret;
private Boolean twoFactorEnabled = false;

// Gerar QR Code para usuário configurar
public String generateTwoFactorSecret(User user) {
    String secret = timeProvider.generateSecretKey();
    user.setTwoFactorSecret(secret);
    userRepository.save(user);
    return qrCodeGenerator.getUriForImage(secret, user.getEmail());
}

// Validar código TOTP no login
public boolean validateTwoFactorCode(User user, String code) {
    if (!user.getTwoFactorEnabled() || user.getTwoFactorSecret() == null) {
        return true; // 2FA não habilitado
    }
    return timeProvider.validateCode(user.getTwoFactorSecret(), code);
}
```

---

### 9. Sem Logout de Todas as Sessões

**Implementação com blacklist de tokens:**

```java
// Criar tabela revoked_tokens
@Entity
public class RevokedToken {
    private String token;
    private LocalDateTime revokedAt;
    private LocalDateTime expiresAt;
}

// No logout
@PostMapping("/logout")
public ResponseEntity<Void> logout(
        @CookieValue("refresh_token") String refreshToken,
        Authentication authentication) {
    
    // Revogar refresh token
    RefreshToken token = refreshTokenRepository.findByToken(refreshToken)
            .orElse(null);
    if (token != null) {
        token.setRevokedAt(LocalDateTime.now());
        refreshTokenRepository.save(token);
    }
    
    // Revogar access token atual (se necessário manter em memória/Redis)
    // ...
    
    return ResponseEntity.noContent().build();
}
```

---

### 10. Sem Auditoria de Segurança

```java
@Entity
@Table(name = "security_audit_logs")
public class SecurityAuditLog {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;
    
    private UUID userId;
    private String action; // LOGIN_SUCCESS, LOGIN_FAILED, PASSWORD_CHANGE, etc
    private String ipAddress;
    private String userAgent;
    private LocalDateTime timestamp;
    private String details;
    
    // Index para queries
    @Index(name = "idx_user_timestamp", columnList = "userId,timestamp")
}
```

---

### 11. Callback OAuth2 Inseguro

**Melhorar validação no AuthCallback.tsx:**

```typescript
// Validar token imediatamente
const token = searchParams.get("token");
if (token) {
  // Validar formato JWT
  if (token.split('.').length !== 3) {
    setStatus("error");
    return;
  }
  
  // Validar token via API antes de salvar
  const isValid = await validateToken(token);
  if (!isValid) {
    setStatus("error");
    return;
  }
  
  // Agora sim, salvar token
  localStorage.setItem("auth_token", token);
}
```

---

### 12. Falta de Timeout de Sessão

**Implementar refresh automático baseado em atividade:**

```typescript
// src/lib/utils/sessionManager.ts

let lastActivity = Date.now();
const INACTIVITY_TIMEOUT = 30 * 60 * 1000; // 30 minutos

export function trackActivity() {
  lastActivity = Date.now();
}

export function checkSessionTimeout() {
  const inactiveTime = Date.now() - lastActivity;
  if (inactiveTime > INACTIVITY_TIMEOUT) {
    logout();
    window.location.href = '/auth?error=session_timeout';
  }
}

// No app.tsx ou layout
useEffect(() => {
  const events = ['mousedown', 'keydown', 'scroll', 'touchstart'];
  events.forEach(event => {
    document.addEventListener(event, trackActivity);
  });
  
  const interval = setInterval(checkSessionTimeout, 60000); // Verificar a cada minuto
  
  return () => {
    events.forEach(event => {
      document.removeEventListener(event, trackActivity);
    });
    clearInterval(interval);
  };
}, []);
```

---

### 13. Sem Detecção de Dispositivo/Geolocalização

**Notificar em novos dispositivos:**

```java
// No login
@PostMapping("/login")
public ResponseEntity<AuthResponse> login(
        @Valid @RequestBody LoginRequest request,
        HttpServletRequest httpRequest) {
    
    AuthResponse response = authService.login(request);
    User user = userRepository.findByEmail(request.getEmail()).orElseThrow();
    
    // Detectar dispositivo
    String userAgent = httpRequest.getHeader("User-Agent");
    String ipAddress = getClientIpAddress(httpRequest);
    
    // Verificar se é dispositivo conhecido
    Device device = deviceRepository.findByUserIdAndUserAgent(user.getId(), userAgent)
            .orElse(null);
    
    if (device == null) {
        // Novo dispositivo - notificar
        emailService.sendNewDeviceNotification(
            user.getEmail(),
            userAgent,
            ipAddress,
            LocalDateTime.now()
        );
        
        // Salvar dispositivo
        device = new Device();
        device.setUserId(user.getId());
        device.setUserAgent(userAgent);
        device.setIpAddress(ipAddress);
        device.setFirstSeen(LocalDateTime.now());
        deviceRepository.save(device);
    }
    
    return ResponseEntity.ok(response);
}
```

---

## 🟢 VULNERABILIDADES BAIXAS

### 14. Inconsistência de Armazenamento

**Padronizar chaves:**

```typescript
// src/lib/constants/storage.ts
export const STORAGE_KEYS = {
  ACCESS_TOKEN: 'zenix_access_token',
  USER: 'zenix_user',
} as const;

// Usar em todo o código
import { STORAGE_KEYS } from '@/lib/constants/storage';
localStorage.setItem(STORAGE_KEYS.ACCESS_TOKEN, token);
```

---

### 15. Falta de Tratamento de Token Expirado

```typescript
// client.ts
if (response.status === 401) {
  const errorData = await response.json().catch(() => ({}));
  
  if (errorData.code === 'TOKEN_EXPIRED') {
    // Mostrar mensagem antes de redirecionar
    localStorage.setItem('auth_error', 'Sessão expirada. Faça login novamente.');
    window.location.href = '/auth?error=session_expired';
    return { data: null, error: { message: 'Sessão expirada' } };
  }
  
  window.location.href = '/auth';
  return { data: null, error: { message: 'Não autorizado' } };
}
```

---

### 16. Logs em Produção

```typescript
// client.ts
const shouldLog = process.env.NODE_ENV === 'development';

if (shouldLog) {
  // Sanitizar dados sensíveis
  const sanitizedBody = body ? sanitizeData(body) : null;
  console.log(`[API] ${method} ${API_BASE_URL}${endpoint}`, sanitizedBody);
}

function sanitizeData(data: any): any {
  if (typeof data !== 'object' || data === null) return data;
  
  const sanitized = { ...data };
  const sensitiveFields = ['password', 'currentPassword', 'newPassword', 'token'];
  
  sensitiveFields.forEach(field => {
    if (sanitized[field]) {
      sanitized[field] = '***REDACTED***';
    }
  });
  
  return sanitized;
}
```

---

### 17. Validação de Senha Inconsistente

**Usar função centralizada:**

```typescript
// Já criado em passwordValidator.ts - usar em todos os lugares
import { validatePassword } from '@/lib/utils/passwordValidator';

// Em register
const validation = validatePassword(registerPassword);
if (!validation.valid) {
  setError(validation.errors.join(", "));
  return;
}

// Em update password
const validation = validatePassword(newPassword);
if (!validation.valid) {
  setError(validation.errors.join(", "));
  return;
}
```

---

### 18. Falta de Tratamento de Conta Desabilitada

```java
// User entity
@Column(nullable = false)
private Boolean enabled = true;

// No login
if (!user.getEnabled()) {
    throw new RuntimeException("Conta desabilitada. Entre em contato com o suporte.");
}
```

---

## 📝 Checklist de Implementação

Use este checklist para acompanhar o progresso:

### Crítico (Implementar primeiro)
- [ ] Refresh tokens com httpOnly cookies
- [ ] Rate limiting em todos endpoints de auth
- [ ] Política de senha forte (mínimo 8 com complexidade)
- [ ] Verificação de email obrigatória
- [ ] Remover credenciais hardcoded
- [ ] Melhorar tratamento de token de reset

### Médio
- [ ] 2FA (TOTP)
- [ ] Logout de todas as sessões
- [ ] Auditoria de segurança
- [ ] Validação melhor do callback OAuth2
- [ ] Timeout de sessão por inatividade
- [ ] Detecção de novo dispositivo

### Baixo
- [ ] Padronizar armazenamento de tokens
- [ ] Melhorar tratamento de token expirado
- [ ] Remover logs sensíveis em produção
- [ ] Centralizar validação de senha
- [ ] Tratamento de conta desabilitada

---

## ⚠️ IMPORTANTE

1. **Teste cada mudança** antes de prosseguir para a próxima
2. **Faça backup** do banco de dados antes de migrations
3. **Implemente incrementalmente** - não tente resolver tudo de uma vez
4. **Documente** qualquer mudança de comportamento
5. **Comunique** mudanças aos usuários (especialmente políticas de senha)

---

## 🔗 Recursos Adicionais

- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [JWT Best Practices](https://datatracker.ietf.org/doc/html/rfc8725)
- [Spring Security OAuth2](https://docs.spring.io/spring-security/reference/servlet/oauth2/index.html)
