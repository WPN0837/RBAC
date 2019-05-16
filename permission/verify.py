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
