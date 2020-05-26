package com.fsd;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.loadbalancer.LoadBalanced;
import org.springframework.cloud.netflix.zuul.EnableZuulProxy;
import org.springframework.context.annotation.Bean;
import org.springframework.web.client.RestTemplate;

import com.fsd.config.LoginFilter;

@SpringBootApplication
@EnableZuulProxy //Zuul Server
public class ZuulApplication {
	public static void main(String[] args) {
        SpringApplication.run(ZuulApplication.class, args);
    }
	

	@Bean
	public LoginFilter loginFilter() {

		return new LoginFilter();

	}
	
	@Bean
	@LoadBalanced
    public RestTemplate restTemplate(){

        return new RestTemplate();

    }

}
