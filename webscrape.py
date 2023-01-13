## created by zayets @ https://github.com/7a6179657473
# written in python

import requests
url=input('enter the domain:')
#
#url = "https://google.com"
response = requests.get(url)
from bs4 import BeautifulSoup
soup = BeautifulSoup(response.text, 'html.parser')
print("debug1")
print("*")
print("*")
print("the url you have selected is "  + url)
print("*")
print("*")
print("+", soup.title)
print("*")
print("+", soup.a)
print("*")
print("*")
