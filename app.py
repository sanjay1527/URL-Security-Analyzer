from flask import Flask, render_template, request, jsonify
from url_analyzer import URLAnalyzer
import json
import datetime

app = Flask(__name__)

# Context processor to make current_year available to all templates
@app.context_processor
def inject_current_year():
    return {'current_year': datetime.datetime.now().year}

@app.route('/', methods=['GET'])
def index():
    current_year = datetime.datetime.now().year
    return render_template('index.html', current_year=current_year)

@app.route('/analyze', methods=['POST'])
def analyze():
    url = request.form.get('url')
    if not url:
        return jsonify({"error": "URL is required"}), 400
    
    # Create URLAnalyzer instance and analyze the URL
    analyzer = URLAnalyzer(url)
    
    # Perform all checks
    analyzer.extract_components()
    analyzer.check_typosquatting()
    analyzer.check_whois()
    analyzer.verify_ssl()
    analyzer.check_blacklists()
    analyzer.analyze_redirections()
    
    # Generate report
    report = analyzer.generate_report()
    
    return jsonify(report)

if __name__ == '__main__':
    app.run(debug=True)