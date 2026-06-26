from flask import Flask, request, render_template_string, jsonify
import subprocess, os, json, shutil, time

app = Flask(__name__)
os.makedirs("./audits", exist_ok=True)

def cleanup_old_audits():
    for folder in os.listdir("./audits"):
        path = os.path.join("./audits", folder)
        if os.path.isdir(path) and (time.time() - os.path.getmtime(path) > 86400):
            shutil.rmtree(path)

cleanup_old_audits()

UI_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en" class="bg-slate-950 text-slate-200">
<head>
    <script src="https://cdn.tailwindcss.com"></script>
    <title>Nomadik | Security Sentinel</title>
</head>
<body class="flex items-center justify-center min-h-screen p-4">
    <div class="w-full max-w-md bg-slate-900 p-8 rounded-3xl border border-slate-800 shadow-2xl">
        <div class="text-center mb-8">
            <h1 class="text-3xl font-extrabold text-white">Nomadik <span class="text-blue-500">Sentinel</span></h1>
            <p class="text-slate-400 mt-2 text-sm">Enterprise-grade security auditing.</p>
        </div>
        
        <form id="auditForm" class="space-y-5">
            <div>
                <label class="block text-xs font-semibold uppercase text-slate-500 mb-1">Target Domain</label>
                <input type="text" name="domain" placeholder="example.com" required 
                       class="w-full p-4 bg-slate-950 border border-slate-700 rounded-xl focus:ring-2 focus:ring-blue-500 outline-none transition">
            </div>
            <div>
                <label class="block text-xs font-semibold uppercase text-slate-500 mb-1">Notification Email</label>
                <input type="email" name="email" placeholder="security@example.com" required 
                       class="w-full p-4 bg-slate-950 border border-slate-700 rounded-xl focus:ring-2 focus:ring-blue-500 outline-none transition">
            </div>
            <button type="submit" class="w-full bg-blue-600 hover:bg-blue-500 py-4 rounded-xl font-bold transition shadow-lg shadow-blue-900/20">
                INITIATE DEEP SCAN
            </button>
        </form>

        <div id="prog" class="hidden mt-8 space-y-2">
            <div class="flex justify-between text-xs font-bold text-slate-400">
                <span id="statusText">Analyzing Infrastructure...</span>
                <span id="percentText">0%</span>
            </div>
            <div class="w-full bg-slate-800 rounded-full h-2 overflow-hidden">
                <div id="bar" class="bg-blue-500 h-2 rounded-full transition-all duration-500" style="width: 0%"></div>
            </div>
        </div>
    </div>

    <script>
        document.getElementById('auditForm').onsubmit = async (e) => {
            e.preventDefault();
            const formData = new FormData(e.target);
            const domain = formData.get('domain');
            
            document.getElementById('prog').classList.remove('hidden');
            e.target.querySelector('button').disabled = true;
            
            await fetch('/audit', {method:'POST', body: formData});
            
            const i = setInterval(async () => {
                const r = await fetch('/status/'+domain); 
                const j = await r.json();
                document.getElementById('bar').style.width = j.percent + '%';
                document.getElementById('percentText').innerText = j.percent + '%';
                document.getElementById('statusText').innerText = j.status;
                if(j.percent >= 100) clearInterval(i);
            }, 2000);
        };
    </script>
</body>
</html>
'''

@app.route('/')
def home(): return render_template_string(UI_TEMPLATE)

@app.route('/audit', methods=['POST'])
def run():
    domain = request.form.get('domain')
    email = request.form.get('email')
    if not domain or not email: return jsonify({"status":"error"}), 400
    
    subprocess.Popen(["docker", "run", "--rm", 
                      "-v", f"{os.path.abspath('./audits')}:/app/audits", 
                      "security-sentinel:latest", domain, email])
    return jsonify({"status":"started"})

@app.route('/status/<d>')
def get_status(d):
    path = f"./audits/{d}/progress.json"
    if os.path.exists(path): return json.load(open(path))
    return {"status":"init", "percent":0}

if __name__ == '__main__': app.run(host='0.0.0.0', port=5000)