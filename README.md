# 运行服务
go run main.go

# 浏览器输入
http://localhost:3000/googleAuth/get?userName=limingyuxia
获取二维码，用微信 腾讯身份验证小程序扫描二维码，获取令牌code

# 浏览器输入
http://localhost:3000/googleAuth/auth?userName=limingyuxia&code=977043
这里的code就是小程序上显示的6位数字，进行验证