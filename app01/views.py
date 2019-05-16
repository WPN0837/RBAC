from django.shortcuts import render, HttpResponse
from app01.models import UserInfo
from permission.models import Permission


# Create your views here.
def login(request):
    if request.method == 'GET':
        name = request.GET.get('name', '')
        pwd = request.GET.get('pwd', '')
        u = UserInfo.objects.filter(username=name, pwd=pwd).first()
        if u:
            request.session['permissions_list'] = list(
                Permission.objects.filter(role__in=u.role.all()).values('url').all())
            return HttpResponse('登录成功')
        else:
            return HttpResponse('登录失败')
