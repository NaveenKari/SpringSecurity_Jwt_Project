package com.springSecurity.demo.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

//Filter,Validate and set Security Context
@Component
public class AuthTokenFilter extends OncePerRequestFilter {

    private JwtUtils jwtUtils;
    private UserDetailsService userDetailsService;

    private static final Logger logger = LoggerFactory.getLogger(AuthTokenFilter.class);

    public AuthTokenFilter(JwtUtils jwtUtils, UserDetailsService userDetailsService) {
        this.jwtUtils = jwtUtils;
        this.userDetailsService = userDetailsService;
    }

    public AuthTokenFilter(){}

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        try{
            String jwt = parseJwt(request);
            if(jwt != null && this.jwtUtils.validateJwtToken(jwt)){

                //need these details to create auth obj
                String username = this.jwtUtils.getUserNameFormJwtToken(jwt);
                UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);

                //need auth object to set security context
                UsernamePasswordAuthenticationToken authenticationObj = new UsernamePasswordAuthenticationToken(
                        userDetails,null, userDetails.getAuthorities()
                );
                //set request details to auth obj
                authenticationObj.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                //set security context
                SecurityContextHolder.getContext().setAuthentication(authenticationObj);
                logger.debug("Roles from JWT: {}",userDetails.getAuthorities());

            }
        }catch (Exception e){
            logger.error("Cannot set user authentication: {}",e);
        }
        //tells spring security to execute remain inbuilt/default filters.
        filterChain.doFilter(request,response);
    }

    private String parseJwt(HttpServletRequest request) {
        return this.jwtUtils.getJwtFromHeader(request);
    }
}
