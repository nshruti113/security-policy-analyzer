"""
Flask Web Application for Security Policy Analyzer
"""
from flask import Flask, render_template, request, redirect, url_for, flash, send_file
from werkzeug.utils import secure_filename
import os
from datetime import datetime
from config_parser import FirewallConfigParser
from security_analyzer import SecurityAnalyzer
from report_generator import ReportGenerator

app = Flask(__name__)
app.secret_key = 'your-secret-key-here-change-in-production'

# Configuration
UPLOAD_FOLDER = '../uploads'
REPORTS_FOLDER = '../reports'
ALLOWED_EXTENSIONS = {'txt', 'conf'}

# Ensure folders exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORTS_FOLDER, exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size


def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/')
def index():
    """Home page"""
    return render_template('index.html')


@app.route('/analyze', methods=['GET', 'POST'])
def analyze_page():
    """Analysis page with file upload"""
    if request.method == 'POST':
        # Check if file was uploaded
        if 'config_file' not in request.files:
            flash('No file uploaded', 'error')
            return redirect(request.url)
        
        file = request.files['config_file']
        
        if file.filename == '':
            flash('No file selected', 'error')
            return redirect(request.url)
        
        if file and allowed_file(file.filename):
            try:
                # Save uploaded file
                filename = secure_filename(file.filename)
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                unique_filename = f"{timestamp}_{filename}"
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                file.save(filepath)
                
                # Get report format preference
                report_format = request.form.get('format', 'all')
                
                # Parse configuration
                parser = FirewallConfigParser(filepath)
                rules = parser.parse()
                
                # Analyze security
                analyzer = SecurityAnalyzer(rules)
                findings = analyzer.analyze()
                
                # Generate reports
                report_gen = ReportGenerator(findings, rules)
                report_files = []
                
                if report_format in ['json', 'all']:
                    json_file = os.path.join(REPORTS_FOLDER, f'report_{timestamp}.json')
                    report_gen.generate_json_report(json_file)
                    report_files.append(os.path.basename(json_file))
                
                if report_format in ['excel', 'all']:
                    excel_file = os.path.join(REPORTS_FOLDER, f'report_{timestamp}.xlsx')
                    report_gen.generate_excel_report(excel_file)
                    report_files.append(os.path.basename(excel_file))
                
                if report_format in ['html', 'all']:
                    html_file = os.path.join(REPORTS_FOLDER, f'report_{timestamp}.html')
                    report_gen.generate_html_report(html_file)
                    report_files.append(os.path.basename(html_file))
                
                # Calculate statistics
                high_count = len([f for f in findings if f['severity'] == 'HIGH'])
                medium_count = len([f for f in findings if f['severity'] == 'MEDIUM'])
                low_count = len([f for f in findings if f['severity'] == 'LOW'])
                
                flash(f'Analysis complete! Found {len(findings)} issues.', 'success')
                
                return render_template('results.html',
                                     filename=filename,
                                     total_rules=len(rules),
                                     total_findings=len(findings),
                                     high_count=high_count,
                                     medium_count=medium_count,
                                     low_count=low_count,
                                     findings=findings,
                                     report_files=report_files)
                
            except Exception as e:
                flash(f'Error analyzing configuration: {str(e)}', 'error')
                return redirect(request.url)
        else:
            flash('Invalid file type. Please upload a .txt or .conf file.', 'error')
            return redirect(request.url)
    
    return render_template('analyze.html')


@app.route('/history')
def history():
    """Show analysis history"""
    try:
        # Get all report files
        reports = []
        if os.path.exists(REPORTS_FOLDER):
            for filename in os.listdir(REPORTS_FOLDER):
                if filename.endswith('.json'):
                    filepath = os.path.join(REPORTS_FOLDER, filename)
                    timestamp = os.path.getctime(filepath)
                    reports.append({
                        'filename': filename,
                        'timestamp': datetime.fromtimestamp(timestamp),
                        'size': os.path.getsize(filepath)
                    })
        
        # Sort by timestamp (newest first)
        reports.sort(key=lambda x: x['timestamp'], reverse=True)
        
        return render_template('history.html', reports=reports)
    
    except Exception as e:
        flash(f'Error loading history: {str(e)}', 'error')
        return render_template('history.html', reports=[])


@app.route('/about')
def about():
    """About page"""
    return render_template('about.html')


@app.route('/download/<filename>')
def download(filename):
    """Download generated report"""
    try:
        filepath = os.path.join(REPORTS_FOLDER, filename)
        return send_file(filepath, as_attachment=True)
    except Exception as e:
        flash(f'Error downloading file: {str(e)}', 'error')
        return redirect(url_for('index'))


@app.errorhandler(404)
def not_found(error):
    """404 error handler"""
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_error(error):
    """500 error handler"""
    return render_template('500.html'), 500


if __name__ == '__main__':
    print("""
    ╔════════════════════════════════════════════════════════════╗
    ║     Security Policy Analyzer - Web Dashboard              ║
    ║     Starting server...                                     ║
    ╚════════════════════════════════════════════════════════════╝
    """)
    print("📍 Server running at: http://127.0.0.1:5000")
    print("🔍 Press Ctrl+C to stop\n")
    
    app.run(debug=True, host='127.0.0.1', port=5000)