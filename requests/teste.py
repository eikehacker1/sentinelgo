import requests

# Teste normal
requests.get("http://localhost:8080/?template=<script>")

# Teste SSTI python 

requests.get("http://localhost:8080/?template={{7 * 7}}")

# Teste suspeito (SQL Injection)
requests.post("http://localhost:8080/?template=", data="SELECT * FROM users WHERE ' OR 1=1 --")
