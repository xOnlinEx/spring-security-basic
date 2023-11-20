package com.xonlinex.springsecuritybasic.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractAuthenticationFilterConfigurer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.SessionManagementConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        //                    form.loginPage("/login");
        return httpSecurity
                // 'cross-site request forgery' es una vulnerabilidad
                // activar si no estas trabajando con formularios
//                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> {
                    // permitimos el acceso test a cualquiera
                    auth.requestMatchers("/test").permitAll();
                    // para el resto pedimos un acceso
                    auth.anyRequest().authenticated();
                })
                .formLogin(form -> {
                    // habilitamos el formulario para aquellos accesos no permitidos
                    form.permitAll();
                    // una vez logeado redirigimos al usuario a /home
                    form.successHandler(authenticationSuccessHandler());
                })
                .sessionManagement(session -> {
                    /*
                    ALWAYS: Siempre se creará una nueva sesión si no hay una disponible.
                    IF_REQUIRED: Se creará una nueva sesión solo si es necesario (por ejemplo, si no hay una sesión actual).
                    NEVER: Nunca se creará una nueva sesión, pero se utilizará una existente si está disponible.
                    STATELESS: No se creará ni utilizará ninguna sesión. Específicamente útil para aplicaciones RESTful sin estado, donde cada solicitud debe llevar toda la información necesaria.
                     */
                    session.sessionCreationPolicy(SessionCreationPolicy.ALWAYS);
                    // URL a la cual redireccionar si se detecta una sesión inválida
                    session.invalidSessionUrl("/login");
                    session.sessionConcurrency(sessionConcurrency -> {
                        // maxima cantidad de session del usuario
                        // ejemplo cuentas netflix pueden tener mas de 1
                        sessionConcurrency.maximumSessions(1);
                        // una vez expirado la session te manda a /login
                        sessionConcurrency.expiredUrl("/login");
                        /*
                        El SessionRegistry almacena información sobre las sesiones activas, como los identificadores de sesión y los nombres de usuario asociados. Esto puede ser útil, por ejemplo, para realizar un seguimiento de los usuarios activos, invalidar sesiones específicas o realizar otras operaciones relacionadas con la gestión de sesiones.
                         */
                        sessionConcurrency.sessionRegistry(sessionRegistry());
                    });
                    /*
                    estrategia de fijación de sesiones. La fijación de sesiones es un ataque en el que un atacante intenta tomar el control de la sesión de un usuario. Para mitigar este riesgo, Spring Security proporciona la capacidad de configurar la estrategia de fijación de sesiones.
                    La fijación de sesiones ocurre cuando un atacante establece o "fija" la sesión de un usuario en una aplicación web. Esto puede suceder de diversas maneras, como mediante la propagación de un identificador de sesión malicioso. Una vez que el atacante ha fijado la sesión, puede tomar el control de la sesión del usuario legítimo.
                    Spring Security proporciona varias estrategias de fijación de sesiones para abordar este problema. Algunas de las estrategias comunes son:

                    none(): No se realiza ninguna acción específica para abordar la fijación de sesiones. Esta es la configuración predeterminada, y significa que Spring Security confía en la configuración del contenedor de servlet para manejar la fijación de sesiones.

                    newSession(): Se crea una nueva sesión y se asigna un nuevo identificador de sesión al usuario después de la autenticación. Esto ayuda a garantizar que la sesión del usuario cambie después de la autenticación, lo que dificulta la fijación de sesiones.

                    migrateSession(): Después de la autenticación, se migra la información de la sesión anterior a una nueva sesión. Esto conserva los datos de la sesión del usuario después de la autenticación, pero cambia el identificador de sesión, lo que dificulta la fijación de sesiones.
                     */
                    session.sessionFixation(SessionManagementConfigurer.SessionFixationConfigurer::migrateSession);
                })
                // autenticacion basica para mandar user y password en los header de la aplicacion
                .httpBasic(Customizer.withDefaults())
                .build();
    }
    @Bean
    public SessionRegistry sessionRegistry(){
        return new SessionRegistryImpl();
    }
    // metodo para redidigirnos a /home
    public AuthenticationSuccessHandler authenticationSuccessHandler(){
        return (request, response, authentication) -> {
            response.sendRedirect("/home");
        };
    }
}
