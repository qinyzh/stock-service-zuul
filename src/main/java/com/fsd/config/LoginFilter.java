package com.fsd.config;

import javax.servlet.http.HttpServletRequest;

import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import com.fsd.utils.JwtTokenUtils;
import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;
import com.netflix.zuul.exception.ZuulException;

/**
 *  编辑ZuulFilter自定义过滤器，用于校验登录
 *  重写zuulFilter类，有四个重要的方法
 *  1.- `shouldFilter`：返回一个`Boolean`值，判断该过滤器是否需要执行。返回true执行，返回false不执行。
 *  2.- `run`：过滤器的具体业务逻辑。
 *  3.- `filterType`：返回字符串，代表过滤器的类型。包含以下4种：
 *      - `pre`：请求在被路由之前执行
 *      - `routing`：在路由请求时调用
 *      - `post`：在routing和errror过滤器之后调用
 *      - `error`：处理请求时发生错误调用
 *  4.- `filterOrder`：通过返回的int值来定义过滤器的执行顺序，数字越小优先级越高
 * @author YuZhuQin
 *
 */
public class LoginFilter extends ZuulFilter{
	private static final String LOGIN_URI = "/auth/login";
	private static final String REGISTER_URI = "/auth/register";
	
	private static final String TOKEN_HEADER = "X-Authorization";
	
	@Autowired
	private RestTemplate restTemplate;


	@Override
	public Object run() throws ZuulException {
		// 登录校验逻辑
        // 1）获取zuul提供的请求上下文对象（即是请求全部内容）
        RequestContext currentContext = RequestContext.getCurrentContext();
        // 2) 从上下文中获取request对象
        HttpServletRequest request = currentContext.getRequest();
        String url = request.getRequestURL().toString();
        // 3) 从请求中获取token
        String token = request.getHeader(TOKEN_HEADER);
        System.out.println("token:"+token);
        if(url.contains(LOGIN_URI)||url.contains(REGISTER_URI)||url.contains("auth/user")||url.contains("file/download")){
			currentContext.setSendZuulResponse(true);
			currentContext.setResponseStatusCode(200);
			currentContext.set("isSuccess", true);
			return null;
		}
        // 4) 判断（如果没有token，认为用户还没有登录，返回401状态码）
        if(token == null || "".equals(token.trim())){
        	// 如果是登录和注册链接，不需要校验token，发起请求		
            // 没有token，认为登录校验失败，进行拦截
            currentContext.setSendZuulResponse(false);
            // 返回401状态码。也可以考虑重定向到登录页
            currentContext.setResponseStatusCode(HttpStatus.UNAUTHORIZED.value());
            currentContext.setResponseBody("Authorization token is empty.");
        }else {
            try {
	        	//有token,JWT验证
            	String token_f = token.replace(JwtTokenUtils.TOKEN_PREFIX, "");
	        	String username = JwtTokenUtils.getUsername(token_f);
	        	//token值有问题拒绝请求
	            if (StringUtils.isEmpty(username)) {
	            	currentContext.setSendZuulResponse(false);
	            	currentContext.setResponseStatusCode(HttpStatus.UNAUTHORIZED.value());
	            	currentContext.setResponseBody("Token auth fail");
	                return null;
	            }
	          //token过期拒绝请求
	            else if (JwtTokenUtils.isExpiration(token_f)) {
	            	currentContext.setSendZuulResponse(false);
	            	currentContext.setResponseStatusCode(HttpStatus.UNAUTHORIZED.value());
	            	currentContext.setResponseBody("Token expired");
	                return null;
	            }
	        	currentContext.addZuulRequestHeader(TOKEN_HEADER, token);
            }catch (Exception e) {
                currentContext.setSendZuulResponse(false);
                currentContext.setResponseStatusCode(HttpStatus.UNAUTHORIZED.value());
                currentContext.setResponseBody("token auth fail");
            }
        	
        }

        // 如果校验通过，可以考虑吧用户信息放入上下文，继续向后执行
        return null;
    }

	@Override
	public boolean shouldFilter() {
		// 默认此类过滤器时false，不开启的，需要改为true
        return true;
	}

	@Override
	public int filterOrder() {
		// 执行顺序为1，值越小执行顺行越靠前
        return 0;
	}

	@Override
	public String filterType() {
		// 登录校验的过滤级别，肯定是第一层过滤
        return "pre";
	}

}
