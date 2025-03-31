from flask import Flask, request, render_template_string
import os

app = Flask(__name__)

@app.route('/')
def index():
    template = request.args.get('template', 'Hello {{ name }}')  # 🚨 Vulnerável a SSTI
    return render_template_string(template, name="Alice")

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8080)