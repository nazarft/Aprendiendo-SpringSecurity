# Aprendiendo-SpringSecurity

## Instalación
Para empezar a usar todas las funcionalidades que nos brinda SpringSecurity, debemos instalar su dependencia:
```java
<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-security</artifactId>
</dependency>

```
Podemos empezar nuestro proyecto con unos métodos básicos:
```java
@RestController
@RequestMapping("/greetings")
public class GreetingsController {
    @GetMapping
    public ResponseEntity<String> sayHello() {
        return ResponseEntity.ok("Hello, World!");
    }
    @GetMapping("/bye")
    public ResponseEntity<String> sayGoodbye() {
        return ResponseEntity.ok("Goodbye, World!");
    }
}
```
Si por ejemplo iniciamos nuestra aplicación, seremos redirigidos a una página para poder iniciar sesión:

![image](https://github.com/user-attachments/assets/dec741a7-c680-477d-bdd3-dee8eaf1a1fa)

Para poder entrar a cualquier endpoint deberemos introducir unas credenciales, el usuario por defecto será **user** y la passsword nos lo dará Spring por la consola.

### ¿Qué esta ocurriendo exactamente?
SpringSecuriy mediante una clase llamada *SecurityFilterChain* impide que podamos entrar a cualquier endpoint sin autorización:
```java
@Bean
        @Order(2147483642)
        SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
            http.authorizeHttpRequests((requests) -> ((AuthorizeHttpRequestsConfigurer.AuthorizedUrl)requests.anyRequest()).authenticated());
            http.formLogin(Customizer.withDefaults());
            http.httpBasic(Customizer.withDefaults());
            return (SecurityFilterChain)http.build();
        }
```
Si te fijas, cualquier petición debe ser autentificada. Luego formLogin nos indica que nos identifiquemos mediante un sistema de inicio de sesión y en caso de que falle, se usaría httpBasic.

## Fundamentos

### Servlet
Un Servlet en Java es una clase que se ejecuta en un servidor web y se utiliza para manejar peticiones HTTP (como GET y POST) y generar respuestas dinámicas, típicamente en forma de páginas web HTML. Es una parte fundamental de la tecnología Java EE (ahora Jakarta EE) para el desarrollo de aplicaciones web.

#### Características principales de los Servlets:
* Permiten procesar solicitudes y generar respuestas personalizadas en tiempo de ejecución.
  
* Independencia de protocolo: Aunque se usan comúnmente con HTTP, pueden manejar otros protocolos.
  
* Ciclo de vida controlado por el contenedor: El contenedor web (como Tomcat, Jetty o GlassFish) administra el ciclo de vida del servlet.
  
* Interacción con datos dinámicos: Pueden interactuar con bases de datos, servicios web, archivos y otras fuentes de datos.

![image](https://github.com/user-attachments/assets/8b175c1d-924b-4e3d-988c-1d3be39872e1)

#### Sesiones
Cuando nos logeamos y accedemos a cualquiera de nuestros endpoints, SpringSecurity gracias a **HttpServlet** nos proporciona un id de sesión.

Este id podemos verlo accediendo al modo desarrollador desde nuestro navegador o también podemos pintarlo nosotros mismos en nuestra aplicación:

```java
public class GreetingsController {
    @GetMapping
    public ResponseEntity<String> sayHello(HttpServletRequest request) {
        return ResponseEntity.ok("Hello, World!" + request.getSession().getId());
    }
}
```
Y el resultado:
![image](https://github.com/user-attachments/assets/f898890e-5429-4bd4-b8c5-b73574468f14)

#### Valores predeterminados
Spring por defecto nos proporciona unos valores de inicio de sesión predeterminados, un username llamado user y un password que genera automáticamente.
Estos valores podemos cambiarlos en nuestro appliacation.properties:
```java
spring.security.user.name= nazar
spring.security.user.password= malik
```
Y ahora cada vez que iniciemos sesión, pondremos esos valores.

### CSRF

CSRF (Cross-Site Request Forgery) es un tipo de ataque en el que un atacante induce a un usuario autenticado a realizar una acción no deseada en una aplicación web en la que está autenticado. Este tipo de ataque explota la confianza que una aplicación tiene en las cookies del navegador del usuario, aprovechando la sesión ya iniciada.

*Ejemplo: Si un usuario autenticado tiene acceso a un sistema bancario, un ataque CSRF podría transferir dinero desde su cuenta a la del atacante sin el conocimiento del usuario.*

#### La solución: generar un token

El uso de un token CSRF es una medida de seguridad que protege contra este tipo de ataques. Aquí están las razones por las que un token CSRF es mejor que confiar en el SessionID:

1. Protección contra el acceso por terceros:
   
El SessionID es gestionado automáticamente por el navegador y se envía en todas las solicitudes al dominio correspondiente, lo que permite que un atacante lo explote fácilmente en ataques CSRF.

Un token CSRF no se envía automáticamente por el navegador; debe incluirse manualmente en la solicitud (generalmente como parte del cuerpo de la solicitud o en un encabezado personalizado), dificultando su explotación.

2. Vinculación con la solicitud específica:
   
Un token CSRF está diseñado para ser único por cada sesión y, en algunos casos, por cada solicitud. Esto asegura que incluso si un atacante crea una solicitud, no podrá generar el token necesario para validarla.

3. Control explícito del desarrollador:

Los SessionIDs son gestionados por el servidor y enviados automáticamente en las cookies. Los tokens CSRF, en cambio, son controlados explícitamente por el desarrollador y solo se validan si se incluyen en la solicitud.

4. Seguridad en aplicaciones sin estado:
   
Los tokens CSRF pueden utilizarse incluso en arquitecturas sin estado (stateless), como aquellas basadas en APIs RESTful, mientras que los SessionIDs están intrínsecamente ligados a una sesión almacenada en el servidor.

El siguiente paso para poner a prueba el uso del token, es crear una clase **Student** junto a su controlador:

Clase Student:

```java
public class Student {
    private Integer id;
    private String name;
    private int marks;

    public Student(Integer id, String name, int marks) {
        this.id = id;
        this.name = name;
        this.marks = marks;
    }

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public int getMarks() {
        return marks;
    }

    public void setMarks(int marks) {
        this.marks = marks;
    }
}
```
Y nuestro controlador:

```java
@RestController
@RequestMapping("/students")
public class StudentController {
    List<Student> students = new ArrayList<>(List.of(
            new Student(1, "Alice", 100),
            new Student(2, "Bob", 90),
            new Student(3, "Charlie", 80)
    ));
    @GetMapping
    public List<Student> getStudents() {
        return students;
    }
    @PostMapping
    public Student addStudent(@RequestBody Student student) {
        students.add(student);
        return student;
    }
    @GetMapping("/csrf-token")
    public CsrfToken getCsrfToken(HttpServletRequest request) {
        return (CsrfToken) request.getAttribute("_csrf");
    }
}
```

Si ahora nos dirigimos a Postman e intentamos crear un nuevo estudiante nos saltará un error *401 Unauthorized*.
Esto es debido a que Spring a modo de seguridad te obliga a proporcionar una clave o token para poder crearlo.
En nuestro caso, si accedemos a la ruta del token podemos obtener ese valor e introducirlo en la petición POST como un HEADER más:

![image](https://github.com/user-attachments/assets/99ec1749-45b0-4452-879e-48274eeb575b)

De esta manera ya podemos realizar la operación.

## Configuración

El siguiente paso será crear una clase de configuración:

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

       return http
                .csrf(customizer -> customizer.disable())
                .authorizeHttpRequests(request -> request.anyRequest().authenticated())
                .httpBasic(Customizer.withDefaults())
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                        )
                .build();
    }
}
```

En este código estamos indicándole a Spring varias cosas, la primera es que nuestra clase es de configuración mediante la anotación *@Configuration*,
lo siguiente que le estamos indicando es que esta clase será la encargada de la configuración de la seguridad mediante *@EnableWebSecurity*.

Con nuestro método así, si accedemos a cualquier endpoint no tendremos ninguna restricción.

#### Parámetro HttpSecurity http:
Es un objeto proporcionado por Spring Security que permite personalizar la configuración de seguridad HTTP.

#### Desactivar CSRF:

```
.csrf(customizer -> customizer.disable())
```
* Desactiva la protección contra ataques CSRF (Cross-Site Request Forgery).
* Esto es útil para aplicaciones que no manejan sesiones (como las API REST que usan tokens o trabajan en modo stateless).

#### Autorización de solicitudes:

```java
.authorizeHttpRequests(request -> request.anyRequest().authenticated())
```
* Todas las solicitudes deben estar autenticadas (requieren que el usuario inicie sesión).

#### Autenticación básica (HTTP Basic):

```java
.httpBasic(Customizer.withDefaults())
```
* Configura la autenticación básica (HTTP Basic Authentication).

#### Gestión de sesiones:

```java
.sessionManagement(session -> 
        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
)
```
* La aplicación no mantendrá sesiones en el servidor.
* Ideal para API REST que usan tokens (como JWT) para autenticación.

## Usuarios

Hasta ahora, estos filtros que estamos creando nos dan la autorización para poder usar las distintas rutas de nuestro controlador. Sin embargo,
nosotros no queremos realmente esto ya que estamos creando un usuario y password explícitamente en el application.properties.

Es decir, estamos usando las funciones por defecto que nos brinda SpringSecurity para poder iniciar sesión y tener las autorizaciones necesarias.
Así que ahora crearemos nuestro forma de identificar al usuario:


![image](https://github.com/user-attachments/assets/b5fdc490-c4e5-4375-b015-535b640424a6)

Así que dentro de nuestra clase de configuración agregaremos un nuevo método:

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    private UserDetailsService userDetailsService;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

       return http
                .csrf(customizer -> customizer.disable())
                .authorizeHttpRequests(request -> request.anyRequest().authenticated())
                .httpBasic(Customizer.withDefaults())
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                        )
                .build();
    }
    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(NoOpPasswordEncoder.getInstance());
        provider.setUserDetailsService(userDetailsService);
        return provider;
    }
}
```
*Dejaremos la encriptación del password para el siguiente apartado.*

Creamos un repositorio:

```java
@Repository
public interface UserRepository extends JpaRepository<User,Integer> {
    User findByUsername(String username);
}
```
El modelo de datos será:
```java
@Entity
@Table(name = "users")
public class User {
    @Id
    private Integer id;
    private String username;
    private String password;


    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    @Override
    public String toString() {
        return "User{" +
                "id=" + id +
                ", username='" + username + '\'' +
                ", password='" + password + '\'' +
                '}';
    }
}
```
Lógicamente, agregamos los datos para conectar la base de datos en el *application.properties*:
```java
spring.datasource.url=jdbc:mysql://localhost:3306/springsecurity
spring.datasource.username=root
spring.datasource.password=12345678
```
Entonces, nuestro UserService será tal que así:
```java
@Service
public class MyUserDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username);
        if(user == null) {
            System.out.println("User not found");
            throw new UsernameNotFoundException("User not found");
        }
        return new UserPrincipal(user);
    }
}
```
Si te fijas, devolvemos un **UserPrincipal**, este será nuestro modelo que implementerá **UserDetails**, un modelo que ofrece SpringSecurity 
que ya viene con métodos predefinidos para ser usados a la hora de crear usuarios:
```java
public class UserPrincipal implements UserDetails {
    private User user;
    public UserPrincipal(User user) {
        this.user = user;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of();
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return UserDetails.super.isAccountNonLocked();
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return UserDetails.super.isCredentialsNonExpired();
    }

    @Override
    public boolean isEnabled() {
        return UserDetails.super.isEnabled();
    }
}
```
Si te fijas, le pasamos al constructor un Usuario que nuestro modelo relacional y cambiamos algunos parametros como la expiración de usuario y devolvemos los valores
de nombre y password de nuestro modelo.

## Encriptación

Ahora mismo tenemos un problema y es el siguiente:


![image](https://github.com/user-attachments/assets/5c0fa2f9-038c-45d1-a6ac-275fdf2af2d8)

Como ves, estamos usando un password visible para todos!!

Imagíante que el usuario usa el mismo password en distintas plataformas, estaríamos entrando en datos privados a los cuales no deberíamos tener acceso.

Nuestro objetivo es encriptar las claves de tal manera que se genere una clave la cual no pueda obtener las credenciales del usuario:


![image](https://github.com/user-attachments/assets/122a4446-a8e5-49dd-93ad-b7812baef606)

Para ello, iremos paso a paso:

En primer lugar, crearemos un controlador **UserController**

```java
@RestController
public class UserController {

    @Autowired
    private UserService userService;

    @PostMapping("/register")
    public User addUser(@RequestBody  User user) {
        return userService.registerUser(user);
    }
}
```
Creamos un servicio llamado **UserService**:

```java
@Service
public class UserService {
    @Autowired
    private UserRepository userRepository;

    public User registerUser(User user) {
        return userRepository.save(user);
    }
}
```

Y ya podemos usar los endpoints para crear un nuevo usuario:

![image](https://github.com/user-attachments/assets/b41f114d-151c-46e8-8090-452c44c671f6)


Sin embargo, de esta manera aún seguimos usando un password sin hashear.

Por lo tanto, haremos uso de una librería que SpringSecurity trae integrada, se llama **BCrypt**:

```java
@Service
public class UserService {
    @Autowired
    private UserRepository userRepository;

    private BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);

    public User registerUser(User user) {
        user.setPassword(encoder.encode(user.getPassword()));
        return userRepository.save(user);
    }
}
```

#### ¿Qué es BCryptPasswordEncoder?
BCryptPasswordEncoder es una clase de Spring Security que proporciona un mecanismo para codificar contraseñas usando el algoritmo BCrypt. Este algoritmo es ampliamente utilizado para almacenar contraseñas de forma segura, ya que incluye:

* Hashing: Convierte una contraseña en un hash no reversible.
* Salting: Agrega un valor aleatorio único (salt) al proceso para evitar ataques de diccionario.
* Work Factor: Permite controlar la dificultad del cálculo del hash.

##### ¿Qué es el número 12 (factor de fuerza)?
El número 12 es el "cost factor" o "factor de trabajo" para el algoritmo BCrypt. Este valor determina cuántas iteraciones internas se realizan para generar el hash. A mayor número:

Mayor seguridad: Aumenta el tiempo necesario para calcular un hash, lo que hace más difícil realizar ataques de fuerza bruta.
Mayor consumo de recursos: El cálculo del hash toma más tiempo y CPU.
El cost factor funciona en una escala logarítmica. Por ejemplo:

Con un cost factor de 10, el cálculo tarda aproximadamente 2ˆ10 = 1024 iteraciones.
Con un cost factor de 12, el cálculo tarda aproximadamente 2ˆ12 = 4096 iteraciones, lo que es 4 veces más lento que un cost factor de 10.

Y si intentamos crear un usuario:
![image](https://github.com/user-attachments/assets/4eab751d-a597-4f4d-b10c-786e43e802c4)

Sin embargo, si intentamos acceder a las rutas para *GET:/students* con uno de los usuarios que hemos creado, veremos que recibimos un 401, pero, por que?

La razón es que en nuestra clase de configuración hemos puesto que no se use una encriptación, así que será tan simple como cambiar una línea:

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    private UserDetailsService userDetailsService;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        return http
                .csrf(customizer -> customizer.disable())
                .authorizeHttpRequests(request -> request.anyRequest().authenticated())
                .httpBasic(Customizer.withDefaults())
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .build();
    }
    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(new BCryptPasswordEncoder(12)); // <----------------------
        provider.setUserDetailsService(userDetailsService);
        return provider;
    }
}
```
## JWT (Json Web Token)

JWT (JSON Web Token) es un estándar abierto (RFC 7519) que define una forma compacta y segura de transmitir información entre dos partes como un objeto JSON. Se utiliza comúnmente para autenticar y autorizar usuarios en aplicaciones web y APIs.

### Características
* Formato Compacto y Auto-Contenido: los JWT están diseñados para ser compactos y fáciles de enviar a través de HTTP (por ejemplo, en los encabezados de autorización).
Son auto-contenidos, ya que pueden incluir toda la información necesaria para verificar su validez, como el identificador del usuario o roles.

* Componentes de un JWT: Un JWT consta de tres partes separadas por puntos (.):

- Header (Encabezado): Describe el tipo de token (JWT) y el algoritmo de firma usado, como HMAC SHA256 o RSA.
```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```
- Payload (Carga útil): Contiene las afirmaciones o claims, que son datos como identificadores de usuario, roles, o cualquier otra información relevante:

```json
{
  "sub": "1234567890",
  "name": "John Doe",
  "admin": true
}
```

- Signature (Firma): Es una firma digital generada para garantizar que el token no ha sido alterado. Se crea usando un secreto compartido o una clave privada.

```scss
HMACSHA256(
  base64UrlEncode(header) + "." +
  base64UrlEncode(payload),
  secret
)
```

* Propósito:

1.Autenticación: Los servidores pueden emitir un JWT cuando un usuario inicia sesión correctamente. El cliente almacena este token y lo envía con cada solicitud para acceder a recursos protegidos.
  
2.Autorización: Contiene información de roles y permisos, lo que permite a los servidores decidir si un usuario puede realizar una acción específica.

* Seguridad: la información en un JWT no está encriptada, sino codificada en Base64Url. Por lo tanto, puede ser decodificada por cualquiera que tenga el token. Para proteger datos sensibles, es común combinar JWT con HTTPS o encriptar los datos antes de incluirlos en el payload.
La firma asegura la integridad del token, garantizando que no se haya modificado.

## Agregarlo al proyecto

Para empezar, debemos agregar un **AuthenticationManager** a nuestro archivo de configuración de seguridad:

```java
 @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }
```
AuthenticationManager es una interfaz central en Spring Security que se encarga de autenticar credenciales proporcionadas por un usuario. Procesa la autenticación y decide si las credenciales son válidas.
Actúa como un orquestador que delega el proceso de autenticación a implementaciones específicas, como DaoAuthenticationProvider o JwtAuthenticationProvider.

Por otro lado *AuthenticationConfiguration* proporciona acceso a la configuración de autenticación predefinida por Spring Security.
En este caso, se utiliza para obtener el AuthenticationManager configurado por Spring Security de forma predeterminada.

Luego ya podemos usar nuestro propio login, así que podemos agregarlo a nuestro controlador:

```java
@PostMapping("/login")
    public String login(@RequestBody User user) {
        return userService.verify(user);
    }
```

Sin embargo, lógicamente no queremos tener que pedir autenticarnos cada vez que iniciemos sesión o intentemos registrarnos, así que modificaremos nuestros filtros en nuestra clase de configuración:

```java
@Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        return http
                .csrf(customizer -> customizer.disable())
                .authorizeHttpRequests(request -> request
                        .requestMatchers("register", "login") <---------
                        .permitAll() <-------------
                        .anyRequest()
                        .authenticated())
                .httpBasic(Customizer.withDefaults())
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .build();
    }
```
En nuestro *UserService* deberemos crear un método encargado de verificar que estemos autenticados:

```java
@Service
public class UserService {
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private AuthenticationManager authenticationManager;

    private BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);

    public User registerUser(User user) {
        user.setPassword(encoder.encode(user.getPassword()));
        return userRepository.save(user);
    }

    public String verify(User user) {
        Authentication authentication =
                authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword()));
        if (authentication.isAuthenticated()) {
            return "User is authenticated";
        }
        return "User is not authenticated";
    }
}
```
Sin embargo, si el usuario está autenticado lo que queremos devolverle es un *token*. Esta lógica la podríamos hacer en el mismo UserService, pero en mi caso crearé un nuevo servicio llamado *JWTService*.

```java
@Service
public class JWTService {
    public String generateToken(User user) {
        
    }
}
```
E inyectamos el servicio en nuestro *UserService*:

```java
@Autowired
    private JWTService jwtService;
```

## Generar tokens

```java
@Service
public class JWTService {
    @Value("${jwt.secret-key}")
    private String secretKey = "";

    public String generateToken(String username) {

        Map<String, Object> claims = new HashMap<>();

        return Jwts.builder()
                .claims()
                .add(claims)
                .subject(username)
                .issuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 30))
                .and()
                .signWith(getkey())
                .compact();

    }

    private Key getkey() {
            byte[] keyBytes = Decoders.BASE64.decode(secretKey);
            return Keys.hmacShaKeyFor(keyBytes);
    }
}
```
La clave para firmar la obtendremos del *application.properties*:

```java
jwt.secret-key = CLAVE SECRETA
```
*  Propiedad secretKey
```java
private String secretKey;
```
Es una cadena vacía que se llenará con la clave secreta codificada en Base64 cuando se genere la clave HMAC SHA-256.

* Método generateToken

```java
public String generateToken(String username) {
    Map<String, Object> claims = new HashMap<>();
    return Jwts.builder()
            .claims()
            .add(claims)
            .subject(username)
            .issuedAt(new Date(System.currentTimeMillis()))
            .setExpiration(new Date(System.currentTimeMillis() + 60 * 60 * 30))
            .and()
            .signWith(getkey())
            .compact();
}
```

- claims:Un mapa que puede contener información adicional (claims personalizados) que deseas incluir en el token.
En este caso, está vacío.

- Jwts.builder(): Construye un JWT. La librería JJWT se utiliza para manejar la creación y validación de tokens JWT.

- .claims().add(claims): asigna los claims.
  
- .subject(username): establece el subject del token, que en este caso es el nombre del usuario.

- .issuedAt(new Date(...)): establece la fecha de emisión del token.

- .setExpiration(new Date(...)): define la fecha de expiración del token.
  
- .signWith(getkey()): firma el token con una clave secreta obtenida del método getkey().
  
- .compact(): finaliza la construcción del token y devuelve el token JWT como una cadena.

* Método getKey()

```java
private Key getkey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
}
```

- Decoders.BASE64.decode(secretKey): decodifica la clave secreta de Base64 a un array de bytes.
  
- Keys.hmacShaKeyFor(keyBytes): convierte los bytes decodificados en una clave HMAC válida para firmar el token JWT.

## Validar token

