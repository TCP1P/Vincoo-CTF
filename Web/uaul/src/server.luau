local Lynx = require("@lynx/lynx")
local serde = require("@lune/serde")
local process = require("@lune/process")

local app = Lynx.new()

local users = {
    { id = 1, username = "admin", password = process.env.ADMIN_PASSWORD or "super_secret_admin_password_2025!", role = "admin" },
}

local sessions = {}
local nextUserId = 2

local function generateToken()
    local chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    local token = ""
    for _ = 1, 32 do
        local idx = math.random(1, #chars)
        token = token .. chars:sub(idx, idx)
    end
    return token
end

local function findUserByUsername(username)
    for _, user in ipairs(users) do
        if user.username == username then
            return user
        end
    end
    return nil
end

local function findUserById(id)
    for _, user in ipairs(users) do
        if user.id == id then
            return user
        end
    end
    return nil
end

local function parseCookies(cookieHeader)
    local cookies = {}
    if not cookieHeader then return cookies end
    for pair in cookieHeader:gmatch("[^;]+") do
        local key, value = pair:match("^%s*([^=]+)=(.+)$")
        if key and value then
            cookies[key:match("^%s*(.-)%s*$")] = value:match("^%s*(.-)%s*$")
        end
    end
    return cookies
end

local function getCurrentUser(c)
    local cookies = parseCookies(c.req.headers["cookie"])
    local token = cookies["session"]
    if not token then return nil end
    local userId = sessions[token]
    if not userId then return nil end
    return findUserById(userId)
end

local BLACKLIST = {
    "load", "loadstring", "loadfile", "dofile",
    "os", "io", "require", "module", "package",
    "process", "fs", "net", "serde",
    "coroutine", "setfenv", "setmetatable",
    "ffi", "jit", "_G", "_ENV", "_VERSION",
}

local DANGEROUS_PATTERNS = {
    "require",
    "dofile",
    "loadfile",
    "loadstring",
    "load%s*%(",
    "_G",
    "_ENV",
    "os%.",
    "io%.",
    "lune",
    "debug%.",
    "package",
    "process",
    "fs%.",
    "setfenv",
    "setmetatable",
    "rawset",
    "rawget",
    "getfenv%s*%(%s*[^0]"
}

local function isTemplateSafe(expr)
    local lowerExpr = expr:lower()
    for _, pattern in ipairs(DANGEROUS_PATTERNS) do
        if lowerExpr:match(pattern:lower()) then
            return false, "Dangerous pattern detected: " .. pattern
        end
    end
    return true
end

local function executeTemplate(template, data)
    local expressions = {}
    for expr in template:gmatch("{{(.-)}}") do
        table.insert(expressions, expr)
    end

    local results = {}
    for i, expr in ipairs(expressions) do
        local safe, err = isTemplateSafe(expr)
        if not safe then
            results[i] = "[BLOCKED: " .. err .. "]"
        else
            local env = {
                data = data,
                string = string,
                math = math,
                tostring = tostring,
                tonumber = tonumber,
                type = type,
                pairs = pairs,
                ipairs = ipairs,
                table = { concat = table.concat },
                getfenv = getfenv,
            }

            local fn, compileErr = loadstring("return " .. expr)
            if not fn then
                results[i] = "[ERROR: " .. tostring(compileErr) .. "]"
            else
                setfenv(fn, env)
                local success, value = pcall(fn)
                if not success then
                    results[i] = "[ERROR: " .. tostring(value) .. "]"
                else
                    results[i] = tostring(value)
                end
            end
        end
    end

    local idx = 0
    local result = template:gsub("{{.-}}", function()
        idx = idx + 1
        return results[idx] or "[ERROR]"
    end)

    return result
end

app:get("/", function(c)
    return c:html([[
<!DOCTYPE html>
<html>
<head>
    <title>Admin Panel</title>
    <style>
        body { font-family: system-ui; background: #0f172a; color: #e2e8f0; padding: 40px; }
        .container { max-width: 500px; margin: 0 auto; }
        h1 { color: #38bdf8; }
        .box { background: #1e293b; padding: 24px; border-radius: 12px; margin: 20px 0; }
        input, button { padding: 12px; margin: 8px 0; width: 100%; box-sizing: border-box; border-radius: 6px; border: 1px solid #334155; }
        input { background: #0f172a; color: #e2e8f0; }
        button { background: #3b82f6; color: white; border: none; cursor: pointer; }
        button:hover { background: #2563eb; }
        a { color: #38bdf8; }
        .tabs { display: flex; gap: 10px; margin-bottom: 20px; }
        .tab { padding: 10px 20px; background: #334155; border-radius: 6px; cursor: pointer; }
        .tab.active { background: #3b82f6; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Admin Panel</h1>
        <p>Enterprise-grade administration system</p>

        <div class="box">
            <h3>Login</h3>
            <input type="text" id="login-user" placeholder="Username">
            <input type="password" id="login-pass" placeholder="Password">
            <button onclick="login()">Login</button>
        </div>

        <div class="box">
            <h3>Register</h3>
            <input type="text" id="reg-user" placeholder="Username">
            <input type="password" id="reg-pass" placeholder="Password">
            <button onclick="register()">Register</button>
        </div>

        <div id="result" class="box" style="display:none;"></div>
    </div>

    <script>
        async function login() {
            const res = await fetch('/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'same-origin',
                body: JSON.stringify({
                    username: document.getElementById('login-user').value,
                    password: document.getElementById('login-pass').value
                })
            });
            const data = await res.json();
            if (res.ok) {
                window.location.href = '/dashboard';
            } else {
                showResult('Error: ' + (data.error || 'Login failed'));
            }
        }

        async function register() {
            const res = await fetch('/register', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    username: document.getElementById('reg-user').value,
                    password: document.getElementById('reg-pass').value
                })
            });
            const data = await res.json();
            showResult(data.message || data.error || 'Done');
        }

        function showResult(msg) {
            const el = document.getElementById('result');
            el.style.display = 'block';
            el.textContent = msg;
        }
    </script>
</body>
</html>
    ]])
end)

app:post("/register", function(c)
    local success, body = pcall(function() return c.req:json() end)
    if not success or type(body) ~= "table" then
        return c:status(400):json({ error = "Invalid JSON" })
    end

    local username = body.username
    local password = body.password
    local role = body.role

    if type(username) ~= "string" or #username < 3 then
        return c:status(400):json({ error = "Username must be at least 3 characters" })
    end
    if type(password) ~= "string" or #password < 6 then
        return c:status(400):json({ error = "Password must be at least 6 characters" })
    end

    if findUserByUsername(username) then
        return c:status(400):json({ error = "Username already exists" })
    end

    local userRole = "user"
    if role == "admin" then
        userRole = "user"
    end

    if type(role) == "string" and role ~= "admin" then
        userRole = role
    end

    local newUser = {
        id = nextUserId,
        username = username,
        password = password,
        role = userRole,
    }
    nextUserId = nextUserId + 1
    table.insert(users, newUser)

    return c:json({ message = "User registered successfully", id = newUser.id })
end)

app:post("/login", function(c)
    local success, body = pcall(function() return c.req:json() end)
    if not success or type(body) ~= "table" then
        return c:status(400):json({ error = "Invalid JSON" })
    end

    local user = findUserByUsername(body.username)
    if not user or user.password ~= body.password then
        return c:status(401):json({ error = "Invalid credentials" })
    end

    local token = generateToken()
    sessions[token] = user.id

    c:header("Set-Cookie", "session=" .. token .. "; Path=/; HttpOnly")
    return c:json({
        message = "Login successful",
        role = user.role
    })
end)

app:get("/dashboard", function(c)
    local user = getCurrentUser(c)
    if not user then
        return c:status(401):json({ error = "Unauthorized" })
    end

    if user.role:lower() == "admin" then
        return c:redirect("/admin")
    end

    return c:html(string.format([[
<!DOCTYPE html>
<html>
<head>
    <title>User Dashboard</title>
    <style>
        body { font-family: system-ui; background: #0f172a; color: #e2e8f0; padding: 40px; }
        .container { max-width: 800px; margin: 0 auto; }
        h1 { color: #38bdf8; }
        .box { background: #1e293b; padding: 24px; border-radius: 12px; margin: 20px 0; }
        .role { background: #22c55e; padding: 4px 12px; border-radius: 20px; font-size: 14px; }
        a { color: #38bdf8; }
        button { padding: 12px 24px; background: #3b82f6; color: white; border: none; border-radius: 6px; cursor: pointer; }
        .stats { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; }
        .stat { background: #334155; padding: 20px; border-radius: 8px; text-align: center; }
        .stat-value { font-size: 32px; font-weight: bold; color: #38bdf8; }
    </style>
</head>
<body>
    <div class="container">
        <h1>User Dashboard</h1>
        <p>Welcome back, <strong>%s</strong>! Your role: <span class="role">%s</span></p>

        <div class="stats">
            <div class="stat">
                <div class="stat-value">3</div>
                <div>Projects</div>
            </div>
            <div class="stat">
                <div class="stat-value">12</div>
                <div>Tasks</div>
            </div>
            <div class="stat">
                <div class="stat-value">89%%</div>
                <div>Progress</div>
            </div>
        </div>

        <div class="box">
            <h3>Your Tasks</h3>
            <p>• Complete project documentation</p>
            <p>• Review code changes</p>
            <p>• Submit weekly report</p>
        </div>

        <div class="box">
            <h3>Notifications</h3>
            <p>You have 2 new messages</p>
        </div>

        <button onclick="logout()">Logout</button>
    </div>
    <script>
        function logout() {
            document.cookie = 'session=; Path=/; Expires=Thu, 01 Jan 1970 00:00:01 GMT;';
            window.location.href = '/';
        }
    </script>
</body>
</html>
    ]], user.username, user.role))
end)

app:get("/admin", function(c)
    local user = getCurrentUser(c)
    if not user then
        return c:status(401):json({ error = "Unauthorized" })
    end

    if user.role:lower() ~= "admin" then
        return c:status(403):json({ error = "Admin access required" })
    end

    return c:html([[
<!DOCTYPE html>
<html>
<head>
    <title>Admin Panel</title>
    <style>
        body { font-family: system-ui; background: #0f172a; color: #e2e8f0; padding: 40px; }
        .container { max-width: 900px; margin: 0 auto; }
        h1 { color: #ef4444; }
        .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
        .box { background: #1e293b; padding: 24px; border-radius: 12px; margin: 20px 0; }
        input, textarea, button { padding: 12px; margin: 8px 0; width: 100%; box-sizing: border-box; border-radius: 6px; border: 1px solid #334155; }
        input, textarea { background: #0f172a; color: #e2e8f0; }
        textarea { min-height: 150px; font-family: monospace; font-size: 14px; }
        button { background: #ef4444; color: white; border: none; cursor: pointer; }
        button:hover { background: #dc2626; }
        .btn-secondary { background: #475569; }
        pre { background: #0f172a; padding: 16px; border-radius: 6px; overflow-x: auto; white-space: pre-wrap; }
        .help { font-size: 13px; color: #94a3b8; margin-top: 8px; }
        .stats { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; }
        .stat { background: #334155; padding: 20px; border-radius: 8px; text-align: center; }
        .stat-value { font-size: 28px; font-weight: bold; color: #ef4444; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Admin Panel</h1>
            <button class="btn-secondary" style="width: auto; padding: 10px 20px;" onclick="logout()">Logout</button>
        </div>

        <div class="stats">
            <div class="stat">
                <div class="stat-value" id="user-count">-</div>
                <div>Total Users</div>
            </div>
            <div class="stat">
                <div class="stat-value">3</div>
                <div>Active Sessions</div>
            </div>
            <div class="stat">
                <div class="stat-value">99.9%</div>
                <div>Uptime</div>
            </div>
        </div>

        <div class="box">
            <h3>Email Template Generator</h3>
            <p>Generate personalized emails using template syntax. Use <code>{{expression}}</code> for dynamic content.</p>

            <textarea id="template">Hello {{data.name}},

Your account balance is: ${{data.balance}}
Account type: {{data.type}}

Generated at: {{tostring(math.floor(12345))}}

Best regards,
Admin Team</textarea>

            <input type="text" id="data-name" placeholder="Recipient Name" value="John">
            <input type="text" id="data-balance" placeholder="Balance" value="1250.00">
            <input type="text" id="data-type" placeholder="Account Type" value="Premium">

            <button onclick="generateEmail()">Generate Email</button>

            <p class="help">Supported: data.*, string.*, math.*, tostring(), tonumber(), type(), getfenv(0)</p>

            <h4>Generated Output:</h4>
            <pre id="result">Output will appear here...</pre>
        </div>
    </div>
    <script>
        async function generateEmail() {
            const template = document.getElementById('template').value;
            const data = {
                name: document.getElementById('data-name').value,
                balance: document.getElementById('data-balance').value,
                type: document.getElementById('data-type').value
            };

            const res = await fetch('/admin/template', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'same-origin',
                body: JSON.stringify({ template, data })
            });
            const result = await res.json();
            document.getElementById('result').textContent = result.output || result.error || 'Error';
        }

        fetch('/admin/stats', { credentials: 'same-origin' })
            .then(r => r.json())
            .then(d => {
                document.getElementById('user-count').textContent = d.userCount || '?';
            });

        function logout() {
            document.cookie = 'session=; Path=/; Expires=Thu, 01 Jan 1970 00:00:01 GMT;';
            window.location.href = '/';
        }
    </script>
</body>
</html>
    ]])
end)

app:get("/admin/stats", function(c)
    local user = getCurrentUser(c)
    if not user or user.role:lower() ~= "admin" then
        return c:status(403):json({ error = "Forbidden" })
    end
    return c:json({ userCount = #users })
end)

app:post("/admin/template", function(c)
    local user = getCurrentUser(c)
    if not user or user.role:lower() ~= "admin" then
        return c:status(403):json({ error = "Forbidden" })
    end

    local success, body = pcall(function() return c.req:json() end)
    if not success or type(body) ~= "table" then
        return c:status(400):json({ error = "Invalid JSON" })
    end

    local template = body.template
    local data = body.data or {}

    if not template then
        return c:status(400):json({ error = "Missing template" })
    end

    if #template > 2000 then
        return c:status(400):json({ error = "Template too long" })
    end

    local output = executeTemplate(template, data)
    return c:json({ output = output })
end)

app:get("/flag", function(c)
    local user = getCurrentUser(c)
    if not user or user.role:lower() ~= "admin" then
        return c:status(403):json({ error = "Forbidden" })
    end
    return c:text("Nice try! The flag is in /flag.txt - can you read it?")
end)

local PORT = tonumber(process.env.PORT) or 3000
print(string.format("Starting on port %d", PORT))
app:serve({ port = PORT })
