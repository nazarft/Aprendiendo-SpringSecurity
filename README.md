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



