## created by zayets @ https://github.com/7a6179657473
# written in python

import requests
from bs4 import BeautifulSoup

url = input('enter the domain (with https/http schema):')
response = requests.get(url)
soup = BeautifulSoup(response.text, 'html.parser')

print("the url you have selected is " + url)
print("All URLs found on the page:")

# Find all <a> tags with href attribute
for link in soup.find_all('a', href=True):
    print(link['href'])
