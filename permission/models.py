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
