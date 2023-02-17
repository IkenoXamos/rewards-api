package com.oberlies.rewards.security;

import com.oberlies.rewards.security.props.CorsConfigurationProps;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.data.repository.query.SecurityEvaluationContextExtension;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true, jsr250Enabled = true)
public class SecurityConfiguration {

    private final CorsConfigurationProps corsConfigurationProps;

    public SecurityConfiguration(CorsConfigurationProps corsConfigurationProps) {
        this.corsConfigurationProps = corsConfigurationProps;
    }

    @Bean
    public SecurityEvaluationContextExtension securityEvaluationContextExtension() {
        return new SecurityEvaluationContextExtension();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .cors(spec -> {
                CorsConfiguration config = new CorsConfiguration();
                config.setAllowedOrigins(corsConfigurationProps.getAllowedOrigins());
                config.setAllowedMethods(corsConfigurationProps.getAllowedMethods());
                config.setAllowedHeaders(corsConfigurationProps.getAllowedHeaders());
                config.setExposedHeaders(corsConfigurationProps.getExposedHeaders());
                config.setAllowCredentials(corsConfigurationProps.isAllowCredentials());
                UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
                source.registerCorsConfiguration("/**", config);
                spec.configurationSource(source);
            })
            .csrf().disable()
            .headers().frameOptions().disable()
            .and()
            .httpBasic().disable()
            .formLogin().disable()
            .authorizeHttpRequests((requests) -> requests
                    .requestMatchers(AntPathRequestMatcher.antMatcher(HttpMethod.GET, "/actuator/**")).permitAll()
                    .requestMatchers(AntPathRequestMatcher.antMatcher("/h2/**")).permitAll()
                    .requestMatchers("/auth/**").anonymous()
                    .anyRequest().authenticated())
            .exceptionHandling().authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))
            .and()
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        return http.build();
    }
}
