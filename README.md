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
Permiten procesar solicitudes y generar respuestas personalizadas en tiempo de ejecución.
Independencia de protocolo: Aunque se usan comúnmente con HTTP, pueden manejar otros protocolos.
Ciclo de vida controlado por el contenedor: El contenedor web (como Tomcat, Jetty o GlassFish) administra el ciclo de vida del servlet.
Interacción con datos dinámicos: Pueden interactuar con bases de datos, servicios web, archivos y otras fuentes de datos.

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
        return http.build();
    }
    
}
```
En este código estamos indicándole a Spring varias cosas, la primera es que nuestra clase es de configuración mediante la anotación *@Configuration*,
lo siguiente que le estamos indicando es que esta clase será la encargada de la configuración de la seguridad mediante *@EnableWebSecurity*.

Con nuestro método así, si accedemos a cualquier endpoint no tendremos ninguna restricción.















## Basic Auth (Autentificación básica)

![image](https://github.com/user-attachments/assets/2ae3029f-f819-4e9f-a381-fbcecc2abe2f)

Para crear una autentifación propia, podemos basarnos con la que nos brinda Spring al principio. Así que creamos nuestra clase SecurityConfig:
```java
@EnableWebSecurity
public class SecurityConfig {
    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(requests ->
            requests.anyRequest().authenticated())
            .httpBasic(Customizer.withDefaults());
        return http.build();
    }
}
```
La anotación *@EnableWebSecurity* le indica a Spring que configuración usar para la autenticación.

#### Postman
Si usamos herramientas como Postman, cuando hagamos la petición, debemos indicar nuestra identificación:


![image](https://github.com/user-attachments/assets/5d48454d-f478-4d3b-8da8-fa8c40690037)


![image](https://github.com/user-attachments/assets/faa2709a-fb69-4e37-976b-561aefbbde4c)

Sin embargo, este método de autenticación no es nada recomendable debido al número tan alto de vulnerabilidades que puede ocasionar.

## Autenticación con JWT


![image](https://github.com/user-attachments/assets/4506625a-5143-40db-a3b2-46374be063b3)



