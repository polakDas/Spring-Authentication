package com.polak.auth.service;

import com.polak.auth.model.CustomUser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.polak.auth.repository.OpenMRSUserRepository;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    private OpenMRSUserRepository userRepository;

    @Autowired
    public CustomUserDetailsService(OpenMRSUserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public CustomUserDetailsService() {}

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        CustomUser customUser = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        return new User(customUser.getUsername(), customUser.getPassword(), customUser.getAuthorities());
    }
}
