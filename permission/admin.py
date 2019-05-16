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
