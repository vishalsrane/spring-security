package com.neustar.loms.ntcs.customauthentication.config.security.filters;

import com.neustar.loms.ntcs.customauthentication.config.security.authentication.CustomAuthentication;
import com.neustar.loms.ntcs.customauthentication.config.security.managers.CustomAuthenticationManager;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@AllArgsConstructor
public class CustomAuthenticationFilter extends OncePerRequestFilter {

    private final CustomAuthenticationManager customAuthenticationManager;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        //1. create an authentication which is not yet authenticated.
        //2. delegate the authentication object to manager.
        //3. get back authentication from manager
        //4. if the object is authenticated then send request to next filter in the chain

        String key = String.valueOf(request.getHeader("key"));
        CustomAuthentication ca = new CustomAuthentication(false, key);

        var authentication = customAuthenticationManager.authenticate(ca);
        if(authentication.isAuthenticated()){
            SecurityContextHolder.getContext().setAuthentication(authentication); //This is where we are saving authentication
            filterChain.doFilter(request, response); //only when authentication worked
        }



    }
}
