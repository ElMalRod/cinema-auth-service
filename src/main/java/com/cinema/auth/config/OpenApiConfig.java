package com.cinema.auth.config;

import com.cinema.auth.constants.AuthConstants;
import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class OpenApiConfig {

    @Bean
    public OpenAPI cinemaAuthOpenApi() {
        return new OpenAPI()
                .info(apiInfo())
                .components(apiComponents())
                .addSecurityItem(new SecurityRequirement().addList(AuthConstants.BEARER_SCHEME_NAME));
    }

    private Info apiInfo() {
        return new Info()
                .title(AuthConstants.OPEN_API_TITLE)
                .version(AuthConstants.OPEN_API_VERSION)
                .description(AuthConstants.OPEN_API_DESCRIPTION);
    }

    private Components apiComponents() {
        SecurityScheme scheme = new SecurityScheme()
                .type(SecurityScheme.Type.HTTP)
                .scheme(AuthConstants.BEARER_SCHEME)
                .bearerFormat(AuthConstants.BEARER_FORMAT);
        return new Components().addSecuritySchemes(AuthConstants.BEARER_SCHEME_NAME, scheme);
    }
}
