package com.ittx.saml2.controller

import com.ittx.saml2.domain.CurrentUser
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.security.core.Authentication
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.userdetails.User
import org.springframework.security.web.DefaultSecurityFilterChain
import org.springframework.security.web.util.matcher.AntPathRequestMatcher
import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping

@Controller
class LandingController {
    private static final Logger LOG = LoggerFactory.getLogger(LandingController.class)

    @RequestMapping("/landing")
    String landing(@RequestBody def user, Model model) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication()
        if (auth == null)
            LOG.debug("Current authentication instance from security context is null")
        else
            LOG.debug("Current authentication instance from security context: "
                    + this.getClass().getSimpleName())
        model.addAttribute("username", 	user.getUsername())
        return "pages/landing"
    }
}
