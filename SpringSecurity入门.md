### 新建SpringBoot项目

#### 启动

在依赖中加入`spring-boot-starter-security`后SpringSecurity将已经启动，启动项目后。之后控制台会打印	`Using generated security password:XXX` 生成的密码默认是一个UUID。然后再去访问接口就会自动重定向到登录页面，默认路径为`/login` 。



#### 用户配置

##### 配置文件

我们可以在`application.properties`中配置默认的用户名和密码

`spring.security.user.name` 	`spring.security.user.password`

在properties中定义的用户名和密码最终是通过set方法注入的，并且通过setPassword注入后，还顺便设置了`passwordGenerated=false`，这样控制台就不会打印默认的密码了。

重启后就可以使用自定义的用户名和密码登录。

##### 配置类

除了上述配置文件这种方式，还可以在配置类中配置用户名和密码。

同时，在配置类中，我们需要配置`PasswordEncoder`来指定加密方式，

###### 为什么要加密

密码如果泄露，并且没有加密，那么别人就可以直接登录你的账号，并且大多人多个网站的账号都是一致的，这样会导致，用户账号极度危险。

###### 加密方案

密码加密一般使用散列函数，这是一种从任何数据中创建数字指纹的方法。散列函数会讲消息或数据压缩成摘要，使得数据量变小，将数据的格式固定下来，然后将数据打乱混合，重新创建一个散列值。散列值通常用一个短的随机字母和数字组成的字符串代表。我们常使用的散列函数有MD5消息摘要算法，安全散列算法。



SpringSecurity提供了多种密码加密方案，官方推荐使用`BCryptPasswordEncoder`,前者使用BCrypt强哈希函数，开发者在使用时可以选择提供strength 和SecureRandom 实例，strength越大，密钥迭代次数越多，密钥迭代次数为2^strength,	strength取值在4-31之间，默认为10。



不同与Shiro中需要自己处理密码加盐，在SpringSecurity中，BCryptPasswordEncoder 将自带了盐。而`BCryptPasswordEncoder`就是`PasswordEncoder`的实现类。



###### PasswordEncoder



`PasswordEncoder`这个接口中实现了三个方法

```java
public interface PasswordEncoder {
	String encode(CharSequence rawPassword);
	boolean matches(CharSequence rawPassword, String encodedPassword);
	default boolean upgradeEncoding(String encodedPassword) {
		return false;
	}
}
```

1. `encode`方法用来对明文密码进行加密，返回加密之后的密文。
2. `matches`方法是一个密码校对方法，用户登录时，将用户传来的明文密码和数据库中保存的密文密码作为参数传入，返回的boolean来判断用户密码是否输入正确
3. `upgradeEncoding` 是否还要进行再次加密，一般来说不用。

###### 配置

```java
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Bean
    public PasswordEncoder passwordEncoder(){
        return NoOpPasswordEncoder.getInstance();
    }


    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("javaboy.org")
                .password("123456")
                .roles("admin");
    }
}
```



1.   我们自定义一个`SecurityConfig` 继承自`WebSecurityConfigurerAdapter` 然后重写里面的`configure` 方法。
2. 我们提供了一个`PasswordEncode`实例，现在暂时先不给密码加密，所以返回一个`NoOpPasswordEncoder`实例。
3. `configure`方法中，我们通过`inMemoryAuthentication`来开启在内存中定义对象，`withUser`中是用户名，`password`则是密码,`roles`是用户角色。
4. 如果需要多个用户，使用`and`相连。

配置完成后，重启项目，Java中的代码配置会覆盖掉xml中的配置。

#### 自定义表单登录页



##### 服务端定义

继续完善前面的SecurityConfig，继续重写他的`configure(WebSecurity web) 和configure(HttpSecurity http)`：

```java
@Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/js/**","/css/**","/images/**");
    }



    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .anyRequest().authenticated()
                .and()
                .formLogin()
                .loginPage("/login.html")
                .permitAll()
                .and()
                .csrf()
                .disable();
    }
```

1. web.ignoring() 用来配置忽略掉的 URL 地址，一般对于静态文件，我们可以采用此操作。
2. 如果我们使用 XML 来配置 Spring Security ，里边会有一个重要的标签 `<http>`，HttpSecurity 提供的配置方法 都对应了该标签。
3. authorizeRequests 对应了 `<intercept-url>`。
4. formLogin 对应了 `<formlogin>`。
5. and 方法表示结束当前标签，上下文回到HttpSecurity，开启新一轮的配置。
6. permitAll 表示登录相关的页面/接口不要被拦截。
7. 最后记得关闭 csrf ，关于 csrf 问题我到后面专门和大家说。

当我们定义了登录页面为/login.html 的时候，Spring Security 也会帮我们自动注册一个/login.html 的接口，这个接口是post请求，用来处理登录逻辑。

在SpringSecurity中，如果我们不做任何配置，默认的登录页面和登录接口的地址都是

+ Get http://locahost:8080/login
+ Post http://locahost:8080/login

而上述代码中，由于我们配置了loginPage 所以默认登录页面地址则为`/login.html`，但其实它还有一个隐藏的操作，就是登录接口地址也变为`/login.html` 也就是现如今存在如下两个请求：

+ Get http://locahost:8080/login.html
+ Post http://locahost:8080/login.html

当然我们也可分开配置。

在`SecurityConfig`中我们可以通过`loginProcessingUrl` 的方法来指定登录接口地址



##### 登录参数配置

在登录表单中的参数为`username` 和 `password` 默认情况下，这个不能变。

配置方式如下:

```java
.and()
.formLogin()
.loginPage("/login.html")
.loginProcessingUrl("/doLogin")
.usernameParameter("name")
.passwordParameter("passwd")
.permitAll()
.and()
```

##### 登录回调

在登录成功后，我们就得分情况处理了，大体上来说，就两种情况：

+ 前后端分离登录
+ 前后端不分离登录

###### 前后端不分离登录

在SpringSecurity中，和登录重定向URL相关的方法有两个：

+ defaultSuccessUrl
+ successForwardUrl

在配置时，这两个只需要配置一个，按需选择即可，两个的区别如下：

1. defaultSuccessUrl 有一个重载的方法，我们先说一个参数的 defaultSuccessUrl 方法。如果我们在 defaultSuccessUrl 中指定登录成功的跳转页面为 `/index`，此时分两种情况，如果你是直接在浏览器中输入的登录地址，登录成功后，就直接跳转到 `/index`，如果你是在浏览器中输入了其他地址，例如 `http://localhost:8080/hello`，结果因为没有登录，又重定向到登录页面，此时登录成功后，就不会来到 `/index` ，而是来到 `/hello` 页面。
2. defaultSuccessUrl 还有一个重载的方法，第二个参数如果不设置默认为 false，也就是我们上面的的情况，如果手动设置第二个参数为 true，则 defaultSuccessUrl 的效果和 successForwardUrl 一致。
3. successForwardUrl 表示不管你是从哪里来的，登录后一律跳转到 successForwardUrl 指定的地址。例如 successForwardUrl 指定的地址为 `/index` ，你在浏览器地址栏输入 `http://localhost:8080/hello`，结果因为没有登录，重定向到登录页面，当你登录成功之后，就会服务端跳转到 `/index` 页面；或者你直接就在浏览器输入了登录页面地址，登录成功后也是来到 `/index`。



相关配置如下：

```java
.and()
.formLogin()
.loginPage("/login.html")
.loginProcessingUrl("/doLogin")
.usernameParameter("name")
.passwordParameter("passwd")
.defaultSuccessUrl("/index")
.successForwardUrl("/index")
.permitAll()
.and()
```

###### 前后端分离登录

除了那两个配置登录成功跳转地址的，适用于前后端不分的开发，还有一个必杀技，那就是successHandler。

successHandler的功能十分强大，甚至已经囊括了defaultSuccessUrl和successForwardUrl的功能：

```java
.successHandler((req, resp, authentication) -> {
    Object principal = authentication.getPrincipal();
    resp.setContentType("application/json;charset=utf-8");
    PrintWriter out = resp.getWriter();
    out.write(new ObjectMapper().writeValueAsString(principal));
    out.flush();
    out.close();
})
```



##### 登录失败回调

与登录成功相似，登录失败也有两个方法：

+ failureForwardUrl
+ failureUrl

**「这两个方法在设置的时候也是设置一个即可」**。failureForwardUrl 是登录失败之后会发生服务端跳转，failureUrl 则在登录失败之后，会发生重定向。

###### 前后端分离登录失败

与前者相同，它也有一个类似的回调：

```java
.failureHandler((req, resp, e) -> {
    resp.setContentType("application/json;charset=utf-8");
    PrintWriter out = resp.getWriter();
    out.write(e.getMessage());
    out.flush();
    out.close();
})
```



##### 注销登录

注销登录的默认接口为`/logout`，我们也可以配置

```java
.and()
.logout()
.logoutUrl("/logout")
.logoutRequestMatcher(new AntPathRequestMatcher("/logout","POST"))
.logoutSuccessUrl("/index")
.deleteCookies()
.clearAuthentication(true)
.invalidateHttpSession(true)
.permitAll()
.and()
```

1. 默认注销的 URL 是 `/logout`，是一个 GET 请求，我们可以通过 logoutUrl 方法来修改默认的注销 URL。
2. logoutRequestMatcher 方法不仅可以修改注销 URL，还可以修改请求方式，实际项目中，这个方法和 logoutUrl 任意设置一个即可。
3. logoutSuccessUrl 表示注销成功后要跳转的页面。
4. deleteCookies 用来清除 cookie。
5. clearAuthentication 和 invalidateHttpSession 分别表示清除认证信息和使 HttpSession 失效，默认可以不用配置，默认就会清除。