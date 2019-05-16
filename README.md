# RBAC
用户权限认证组件包括权限model类和中间件类

model类介绍
Permission
权限类

权限基本信息包括title：权限名称 url：权限具体url

Role
角色类

角色类包括title：角色名称 permission：角色的权限 

权限和角色多对多关系 

用户类需要对Role类设置多对多映射

Whitelist
白名单类

白名单包括title：权限名称 url：权限具体url 

白名单内存放的是系统放行不进行权限校验的url

NeedLogin
登录验证包括title:url标题 url：具体url

登录验证表存放的是需要登录才能进行操作或权限校验的url，如果没有登录则会重定向到登录页面

models.py

from django.db import models


class Permission(models.Model):
    '''
    权限基本信息包括title：权限名称 url：权限具体url
    '''
    title = models.CharField(max_length=32, verbose_name='权限名称')
    url = models.CharField(max_length=200, verbose_name='url')

    def __str__(self):
        return self.title

    class Meta:
        verbose_name = '权限'
        verbose_name_plural = verbose_name


class Role(models.Model):
    '''
    角色类包括title：角色名称 permission：角色的权限
    权限和角色多对多关系
    用户类需要对Role类设置多对多映射
    '''
    title = models.CharField(max_length=32, verbose_name='角色名称')
    permission = models.ManyToManyField(Permission, verbose_name='权限')

    def __str__(self):
        return self.title

    class Meta:
        verbose_name = '角色'
        verbose_name_plural = verbose_name


class Whitelist(models.Model):
    '''
    白名单包括title：权限名称 url：权限具体url
    白名单内存放的是系统放行不进行权限校验的url
    '''
    title = models.CharField(max_length=32, verbose_name='权限名称')
    url = models.CharField(max_length=200, verbose_name='url')

    def __str__(self):
        return self.title

    class Meta:
        verbose_name = '白名单'
        verbose_name_plural = verbose_name


class NeedLogin(models.Model):
    '''
    登录验证包括title:url标题 url：具体url
    登录验证表存放的是需要登录才能进行操作或权限校验的url，如果没有登录则会重定向到登录页面
    '''
    title = models.CharField(max_length=32, verbose_name='url标题')
    url = models.CharField(max_length=200, verbose_name='url')

    def __str__(self):
        return self.title

    class Meta:
        verbose_name = '登录验证表'
        verbose_name_plural = verbose_name

中间件类介绍
VerifyPermissions
权限认证中间件实现了process_request和process_view方法。中间件在初始化时会从数据库更新白名单列表和需要登录认证的url列表，这个中间件实现了用户访问权限认证，登录认证功能。

verify.py

from django.shortcuts import render, HttpResponse, redirect
from permission.models import Whitelist, NeedLogin
from django.utils.deprecation import MiddlewareMixin
import re
from django.conf import settings


class VerifyPermissions(MiddlewareMixin):
    # 只在中间件加载时执行一次
    # 获取白名单列表
    whitelist = Whitelist.objects.values('url').all()
    # 获取需要登录的url列表
    needLogin_list = NeedLogin.objects.values('url').all()

    def process_request(self, request):
        '''
        对用户的请求和登录验证的url进行匹配，如果匹配成功且用户没有登录，则重定向到登录页面
        需要在settings.py配置LOGIN_URL
        :param request:
        :return:
        '''
        current_url = request.path
        # 从session中取用户登录的数据，在登录视图函数内，登录成功需要在session中存储登录用户信息，这里使用user作为登录用户信息的key
        user = request.session.get("user", "")
        # 校验是否是登录验证表的内容，如果是且已登录则放行，如果不是登录验证表的内容则会放行到urls.py，如果未登录则重定向到登录页面
        for url in self.needLogin_list:
            ret = re.fullmatch(url['url'], current_url)
            if ret:
                if user:
                    return
                else:
                    return redirect(settings.LOGIN_URL)

    def process_view(self, request, view_func, view_args, view_kwargs):
        '''
        根据中间中process_*方法执行的顺序，process_view方法是在请求到达urls.py之后在执行view.py视图函数之前执行的
        使用process_view方法不使用process_request是因为如果用户输入了找不到的路径，可以先提示404，不会先提示权限问题
        '''
        current_url = request.path
        # 校验是否是白名单的内容，如果是则放行
        for url in self.whitelist:
            ret = re.fullmatch(url['url'], current_url)
            if ret:
                return
        # 从session中获取权限列表
        permissions_list = request.session.get('permissions_list', [])
        # 校验是否是权限内的内容,如果不是提示权限不够
        for url in permissions_list:
            ret = re.fullmatch(url['url'], current_url)
            if ret:
                return
        else:
            # 可设置自定义页面
            return HttpResponse('权限不够')

管理员通过django的admin更新白名单或者登录验证表时需要及时更新中间件中的白名单列表和登录验证url列表，避免重启项目。这里使用重写admin.ModelAdmin的save_model和delete_model方法。
admin.py

from django.contrib import admin
from permission.models import *
from permission.verify import VerifyPermissions


class WhitelistAdmin(admin.ModelAdmin):
    '''
    由于只在中间件加载第一次时加载白名单，所以对白名单内容做修改时，应对中间件中内容更新
    '''

    def save_model(self, request, obj, form, change):
        obj.save()
        VerifyPermissions.whitelist = Whitelist.objects.values('url').all()

    def delete_model(self, request, obj):
        obj.delete()
        VerifyPermissions.whitelist = Whitelist.objects.values('url').all()


class NeedLoginAdmin(admin.ModelAdmin):
    '''
    由于只在中间件加载第一次时加载登录验证表，所以对登录验证表内容做修改时，应对中间件中内容更新
    '''

    def save_model(self, request, obj, form, change):
        obj.save()
        VerifyPermissions.needLogin_list = NeedLogin.objects.values('url').all()

    def delete_model(self, request, obj):
        obj.delete()
        VerifyPermissions.needLogin_list = NeedLogin.objects.values('url').all()


admin.site.register(Permission)
admin.site.register(Role)
admin.site.register(Whitelist, WhitelistAdmin)
admin.site.register(NeedLogin, NeedLoginAdmin)

使用说明：
组件Github地址：https://github.com/WPN0837/RBAC

PS：Github上是组件的一个使用示例

只需要把permission下的内容复制到需要权限认证的项目中即可使用

在使用这个组件的项目中注册这个组件,在settings.py的INSTALLED_APPS添加'permission.apps.PermissionConfig',例如：

INSTALLED_APPS = [
    '''
    'permission.apps.PermissionConfig',
]
添加中间件，在settings.py的MIDDLEWARE添加'permission.verify.VerifyPermissions',例如：

MIDDLEWARE = [
    '''
    'permission.verify.VerifyPermissions',
]
PS:VerifyPermissions一定要写在SessionMiddleware后面，因为VerifyPermissions使用到了session

使用需要注意的地方：
在项目定义User类的地方需要先引入permission.models下的Role类

例如from permission.models import Role
再在User绑定User类与Role类多对多映射关系

具体如：

class UserInfo(models.Model):
    username = models.CharField(max_length=20)
    pwd = models.CharField(max_length=20)
    # 绑定用户与角色多对多映射关系
    role = models.ManyToManyField(Role, verbose_name='角色')

    def __str__(self):
        return self.username

在配置文件settings.py文件中需要配置登录的URL，要与urls.py文件中相同，例如：

# settings.py
# 也可使用登录url的别名
LOGIN_URL = "/login/"

# urls.py
urlpatterns = [
    path('admin/', admin.site.urls),
    path('', index),
    # 登录的url，也可以使用别名
    path('login/', login),
]

在用户登录视图函数里，如果登录成功应当把用户信息和用户权限信息保存到用户的session中，例如：

def login(request):
    if request.method == 'GET':
        name = request.GET.get('name', '')
        pwd = request.GET.get('pwd', '')
        u = UserInfo.objects.filter(username=name, pwd=pwd).first()
        if u:
            # 保存用户信息
            request.session['user'] = name
            # 保存用户权限信息
            request.session['permissions_list'] = list(
                Permission.objects.filter(role__in=u.role.all()).values('url').all())
            return HttpResponse('登录成功')
        else:
            return HttpResponse('登录失败')

具体保存到session里的数据的key由中间件类VerifyPermissions的process_request（使用了user）和process_view（使用了permissions_list）方法里使用到session的地方决定，可自己修改。

在添加完组件后，首先迁移数据库文件，然后把中间件VerifyPermissions注释掉，再进入django admin管理后台，在白名单中添加/admin/.*这个url，权限名称可以设置成admin或者其他的，再取消中间件VerifyPermissions的注释，因为没有admin后台的url添加进白名单，会提示没有权限访问/admin/开头的url。
博客地址：https://blog.csdn.net/qq_35152505/article/details/90255754

