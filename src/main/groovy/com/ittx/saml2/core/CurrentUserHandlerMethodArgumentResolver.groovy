package com.ittx.saml2.core

import com.ittx.saml2.domain.CurrentUser
import org.springframework.core.MethodParameter
import org.springframework.lang.Nullable
import org.springframework.security.core.Authentication
import org.springframework.security.core.userdetails.User
import org.springframework.stereotype.Component
import org.springframework.web.bind.support.WebArgumentResolver
import org.springframework.web.bind.support.WebDataBinderFactory
import org.springframework.web.context.request.NativeWebRequest
import org.springframework.web.method.support.HandlerMethodArgumentResolver
import org.springframework.web.method.support.ModelAndViewContainer

import java.security.Principal

@Component
class CurrentUserHandlerMethodArgumentResolver implements HandlerMethodArgumentResolver{
    @Override
    boolean supportsParameter(MethodParameter parameter) {
        return parameter.getParameterAnnotation(CurrentUser.class) != null && parameter.getParameterType().equals(User.class)
    }

    @Override
    Object resolveArgument(MethodParameter parameter, @Nullable ModelAndViewContainer mavContainer, NativeWebRequest webRequest, @Nullable WebDataBinderFactory binderFactory) throws Exception {
        if (!this.supportsParameter(parameter)) return WebArgumentResolver.UNRESOLVED
        Principal principal = (Principal) webRequest.getUserPrincipal()
        return (User) ((Authentication) principal).getPrincipal()
    }
}
