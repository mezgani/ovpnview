import time, socket, re
from whois import *
from connexion import *
from mod_python import util
from mod_python import Session, Cookie

username = "admin"
password = "admin"
host="192.168.0.1"
port=5555
vpnpasswd="OpenVPNraCK"
version=4


main_page= """
 <html>
 <head><title>OpenVPN status</title>
 <meta http-equiv="Content-Type" content="text/html"; charset="iso-8859-1"/>
 <link rel="icon" href="../img/whois.png" type="image/png">
 <meta name="description" content="OpenVPN status">
 <meta http-equiv="refresh" content="300; URL=./main">
 <script type="text/javascript" src="../js/jquery.js"></script>
 <script type="text/javascript" src="../js/thickbox.js"></script>
 <link rel="stylesheet" href="../css/thickbox.css" type="text/css" media="screen" />
 <link href="../css/theme.css" rel="stylesheet" type="text/css">
 </head>
 <body>
 <div style="text-align:center;background:#ffffcc;">
 <br>
 <div align=\"left\"><img src=\"../img/openvpn_logo.png\"></div>
 <div align=\"center\"><h3>OpenVPN status</h3></div><div align=\"right\"> %s connected.</div>
 <div align=\"right\"><b><a href=\"./logout\">Logout</a></b></div><br>
 <table id=\"tasklist\"><thead><tr class=\"severity5\">
 <td class=\"severity\">Common Name</td>
 <td class=\"severity\">Real Address</td>
 <td class=\"severity\">Virtual Address</td>
 <td class=\"severity\">Bytes Sent</td>
 <td class=\"severity\">Bytes Received</td>
 <td class=\"severity\">Connected Since</td>
 <td class=\"severity\">Last Active</td>
 <td class=\"severity\">Some operation</td>
 </tr>
 """

def index(req): 

  req.content_type = 'text/html'
  s = """
<html>
<head><title>Login</title>
<meta http-equiv=\"Content-Type\" content=\"text/html\"; charset=utf-8\"iso-8859-1\"/>
<link rel=\"icon\" href=\"../img/whois.png\" type=\"image/png\">
<meta name=\"description\" content=\"OpenVPN status\">
<link href=\"../css/theme.css\" rel=\"stylesheet\" type=\"text/css\">

</head>
<body>
<center>
<form action=\"./login\" method=\"POST\">
<table class=\"login\" background=\"../img/header.jpg\">
<tr>
<td><label><font color=\"white\">Username</font>
<input type=\"text\" name=\"username\" value=\"admin\" size=\"20\" maxlength=\"20\"></label>
</td>
<td><label><font color=\"white\">Password </font>
<input type=\"password\" name=\"password\" value=\"admin\" size=\"20\" maxlength=\"20\"></label>
</td>
<td>
<br><br>
<label><font color=\"white\">Remember me? </font>
<input type=\"checkbox\" name=\"remember\"/> 
</td><td>
<br><br><br>
<input class=\"adminbutton\" type=\"submit\" value=\"Login!\">
</td>
</tr>
</form>
</table>
</center>
"""
  req.write(s)

footer="""
</body>
</html>
"""

popup="""
<html>
<head><title></title>
<style type=\"text/css\">
body ,th{
  margin              : 0px;
  padding             : 0px;
  background-color    : green;
  color               : #000;
  font-size           : 10px;
  font-family         : Arial, Helvetica, sans-serif;
}
</style>
</head>
<body>

"""

def headers(num):
   return main_page % num

def exception(req):
    req.write("</table></div>")
    req.write("</body></html>")
    exit

def parse(req):

    req.content_type="text/html"
    sock=connexion(host, port, vpnpasswd, 'status',version)
    data=sock.interact()
    tab1=re.findall("(.+),(\d+\.\d+\.\d+\.\d+\:\d+),(\d+),(\d+),(.+)", data)
    tab2=re.findall("(\d+\.\d+\.\d+\.\d+),(.+),(\d+\.\d+\.\d+\.\d+\:\d+),(.+)", data)

    num=(len(tab1)+len(tab2))/2                     
    req.write(headers(num))
    
    if len(tab2)==0:
       exception(req)
    
    for i in xrange(len(tab1)):
       for j in xrange(len(tab2)):
         if tab2[j][1]==tab1[i][0]:
            sendv=float(tab1[i][2])/1024
	    receiv=float(tab1[i][3])/1024
	    req.write("<tr class=\"severity6\" ")
	    req.write("onmouseover=\"this.className=\'severity6_over\'; ")
	    req.write("this.style.cursor=\'hand\'\" ")
	    req.write("onmouseout=\"this.className = \'severity6\'; ")
	    req.write("this.style.cursor = \'default\'\">\n")
	    req.write("<td class=\"severity\">%s</td>\n" % tab1[i][0])
            req.write("<td class=\"severity\">%s</td>\n" % tab1[i][1]) 
	    req.write("<td class=\"severity\">%s</td>\n" % tab2[j][0]) 
	    req.write("<td class=\"severity\">%.2f KB</td>\n" % sendv)
	    req.write("<td class=\"severity\">%.2f KB</td>\n" % receiv)
	    req.write("<td class=\"severity\">%s</td>\n" % tab1[i][4])
	    req.write("<td class=\"severity\">%s</td>\n" % tab2[j][3])
	    req.write("<td class=\"severity\">\n")
	    req.write("<a href=\"./kill?cn=%s\">" % tab1[i][0])
	    req.write("<img src=../img/stop.png alt=\"kill\" title=\"kill\"></a>&nbsp;&nbsp\n")
	    req.write("<a href=\"./whois?cn=%s\"  class=\"thickbox\">" % tab1[i][1].split(':')[0])
	    req.write("<img src=\"../img/whois.png\" alt=\"whois\" title=\"whois\">")
	    req.write("</a>&nbsp;&nbsp\n</td>")
	    req.write("</tr>\n") 
    
    req.write("</table></div>")
    req.write("</body></html>")

def kill(req):
    req.content_type = 'text/html'
    if check(req):
    	try:
	      if req.form['cn'] is not None:
      		 cmd="kill "+req.form['cn']
		 sock=connexion(host, port, vpnpasswd, cmd)
 		 sock.interact()
	 	 util.redirect(req,"./main")
	except Exception, e:
	      raise(str(e)) 
    else:
		 util.redirect(req,'./login')

def check(req):
	req.content_type = 'text/html'
        session = Session.Session(req)
        if session.has_key('valid') and  session['valid'] == password:
		return True
	else:
		return False

def whois(req):
	req.content_type = 'text/html'
	if check(req):
		try:
      			if req.form['cn'] is not None:
				ip=req.form['cn']
	        		obj=cwhois("whois.lacnic.net",ip,'4')
				data=obj.onWhois()
				data=data.replace('\n','<br>')
	        		req.write("%s" % popup)
	        		req.write("%s" % data)
		        	req.write("%s" % footer)
		except Exception, e:
      			raise(str(e))
	else:
		 util.redirect(req,'./login')


def main(req):
    req.content_type = 'text/html'
    session = Session.Session(req)
    cookies = Cookie.get_cookies(req, Cookie.MarshalCookie,secret="cooks")
    if cookies.has_key('sessid'):
        cookie = cookies['sessid']
        if type(cookie) is Cookie.MarshalCookie:
            data = cookie.value
            session['valid'] = password
            session.save()
    else:
        if session.is_new():
            util.redirect(req,'./login')
        if session['valid'] != password:
            util.redirect(req,'./login')
    parse(req)

def login(req):
    req.content_type = "text/html"
    if req.method == 'POST':
        if req.form['username'] == username and req.form['password'] == password:
            session = Session.Session(req)
            session['valid'] = password
            session.save()
            if req.form.has_key('remember') and req.form['remember']:
                value = {'username': req.form['username'], 'passwword':req.form['password']}
                Cookie.add_cookie(req,Cookie.MarshalCookie('sessid', \
		value,'cooks'),expires=time.time() + 3000000)
            util.redirect(req,'./main')
        else:
	    
            index(req)
            req.write("<center><b><font color=\"white\">\
	    login or password incorrect</b></font></center>")
            req.write(footer)
    else:
        index(req)
        req.write(footer)

def logout(req):
    req.content_type = "text/html"
    session = Session.Session(req)
    if session.has_key('valid'):
        session.delete()
    util.redirect(req,'./main')

