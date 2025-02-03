from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from database import get_db_connection
from werkzeug.security import generate_password_hash, check_password_hash
import mysql.connector
from functools import wraps

app = Flask(__name__)  # 改回默认配置
app.secret_key = 'your_secret_key_here'  # 更改为随机字符串

# 添加一个装饰器来注入 is_admin 函数到所有模板中
def inject_is_admin():
    return dict(is_admin=is_admin)

# 在 app 初始化后添加
app.context_processor(inject_is_admin)

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return redirect(url_for('chat'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute('INSERT INTO users (username, password) VALUES (%s, %s)',
                         (username, password))
            conn.commit()
            flash('注册成功！请登录。')
            return redirect(url_for('login'))
        except:
            flash('用户名已存在！')
        finally:
            cursor.close()
            conn.close()
            
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute('SELECT * FROM users WHERE username = %s AND password = %s', 
                      (username, password))
        user = cursor.fetchone()
        
        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            return redirect(url_for('chat'))
        else:
            flash('用户名或密码错误！')
            
        cursor.close()
        conn.close()
        
    return render_template('login.html')

@app.route('/chat', methods=['GET', 'POST'])
def chat():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    if request.method == 'POST':
        # 检查用户是否被禁言
        cursor.execute('SELECT is_muted FROM users WHERE id = %s', (session['user_id'],))
        user = cursor.fetchone()
        if user['is_muted']:
            flash('您已被禁言！')
            return redirect(url_for('chat'))
            
        receiver_id = request.form['receiver_id']
        message = request.form['message']
        
        cursor.execute('INSERT INTO messages (sender_id, receiver_id, content) VALUES (%s, %s, %s)',
                      (session['user_id'], receiver_id, message))
        conn.commit()
    
    cursor.execute('SELECT id, username FROM users WHERE id != %s', (session['user_id'],))
    users = cursor.fetchall()
    
    # 修改消息查询，排除被隐藏的消息
    cursor.execute('''
        SELECT m.*, u1.username as sender_name, u2.username as receiver_name 
        FROM messages m 
        JOIN users u1 ON m.sender_id = u1.id 
        JOIN users u2 ON m.receiver_id = u2.id 
        WHERE (sender_id = %s OR receiver_id = %s)
        AND m.id NOT IN (
            SELECT message_id FROM hidden_messages WHERE user_id = %s
        )
        ORDER BY timestamp DESC
    ''', (session['user_id'], session['user_id'], session['user_id']))
    messages = cursor.fetchall()
    
    cursor.close()
    conn.close()
    
    return render_template('chat.html', users=users, messages=messages)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/admin')
def admin_panel():
    if 'user_id' not in session or not is_admin(session['user_id']):
        flash('无权限访问！')
        return redirect(url_for('chat'))
        
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    # 获取所有用户
    cursor.execute('SELECT * FROM users WHERE id != %s', (session['user_id'],))
    users = cursor.fetchall()
    
    # 获取所有消息
    cursor.execute('''
        SELECT m.*, u1.username as sender_name, u2.username as receiver_name 
        FROM messages m 
        JOIN users u1 ON m.sender_id = u1.id 
        JOIN users u2 ON m.receiver_id = u2.id 
        ORDER BY timestamp DESC
    ''')
    messages = cursor.fetchall()
    
    # 获取所有群聊
    cursor.execute('''
        SELECT g.*, u.username as owner_name, 
               COUNT(gm.id) as member_count
        FROM chat_groups g
        JOIN users u ON g.owner_id = u.id
        LEFT JOIN group_members gm ON g.id = gm.group_id
        GROUP BY g.id
    ''')
    groups = cursor.fetchall()
    
    # 获取用户群聊关系
    cursor.execute('''
        SELECT u.username, GROUP_CONCAT(g.name) as group_names
        FROM users u
        LEFT JOIN group_members gm ON u.id = gm.user_id
        LEFT JOIN chat_groups g ON gm.group_id = g.id
        GROUP BY u.id
    ''')
    user_groups = cursor.fetchall()
    
    cursor.close()
    conn.close()
    
    return render_template('admin.html', 
                         users=users, 
                         messages=messages, 
                         groups=groups,
                         user_groups=user_groups)

def is_admin(user_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute('SELECT is_admin FROM users WHERE id = %s', (user_id,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()
    print(f"Checking admin status for user {user_id}: {user}")  # 添加调试信息
    return user and user['is_admin']

@app.route('/admin/user/delete/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if not is_admin(session['user_id']):
        return jsonify({'success': False, 'message': '无权限！'})
        
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute('DELETE FROM messages WHERE sender_id = %s OR receiver_id = %s', (user_id, user_id))
        cursor.execute('DELETE FROM hidden_messages WHERE user_id = %s', (user_id,))
        cursor.execute('DELETE FROM users WHERE id = %s', (user_id,))
        conn.commit()
        return jsonify({'success': True})
    except:
        return jsonify({'success': False, 'message': '删除失败！'})
    finally:
        cursor.close()
        conn.close()

@app.route('/admin/user/mute/<int:user_id>', methods=['POST'])
def toggle_mute_user(user_id):
    if not is_admin(session['user_id']):
        return jsonify({'success': False, 'message': '无权限！'})
        
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute('UPDATE users SET is_muted = NOT is_muted WHERE id = %s', (user_id,))
        conn.commit()
        return jsonify({'success': True})
    except:
        return jsonify({'success': False, 'message': '操作失败！'})
    finally:
        cursor.close()
        conn.close()

@app.route('/admin/message/delete/<int:message_id>', methods=['POST'])
def admin_delete_message(message_id):
    if not is_admin(session['user_id']):
        return jsonify({'success': False, 'message': '无权限！'})
        
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute('DELETE FROM hidden_messages WHERE message_id = %s', (message_id,))
        cursor.execute('DELETE FROM messages WHERE id = %s', (message_id,))
        conn.commit()
        return jsonify({'success': True})
    except:
        return jsonify({'success': False, 'message': '删除失败！'})
    finally:
        cursor.close()
        conn.close()

@app.route('/admin/reset', methods=['POST'])
def reset_system():
    if not is_admin(session['user_id']):
        return jsonify({'success': False, 'message': '无权限！'})
        
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute('DELETE FROM hidden_messages')
        cursor.execute('DELETE FROM messages')
        cursor.execute('DELETE FROM users WHERE is_admin = FALSE')
        conn.commit()
        return jsonify({'success': True})
    except:
        return jsonify({'success': False, 'message': '重置失败！'})
    finally:
        cursor.close()
        conn.close()

@app.route('/message/hide/<int:message_id>', methods=['POST'])
def hide_message(message_id):
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': '请先登录！'})
        
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute('INSERT INTO hidden_messages (user_id, message_id) VALUES (%s, %s)',
                      (session['user_id'], message_id))
        conn.commit()
        return jsonify({'success': True})
    except:
        return jsonify({'success': False, 'message': '操作失败！'})
    finally:
        cursor.close()
        conn.close()

@app.route('/admin/user/create', methods=['POST'])
def create_user():
    if not is_admin(session['user_id']):
        return jsonify({'success': False, 'message': '无权限！'})
    
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'success': False, 'message': '用户名和密码不能为空！'})
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute('INSERT INTO users (username, password) VALUES (%s, %s)',
                      (username, password))
        conn.commit()
        return jsonify({'success': True})
    except mysql.connector.Error as err:
        if err.errno == 1062:  # 重复键错误
            return jsonify({'success': False, 'message': '用户名已存在！'})
        return jsonify({'success': False, 'message': '创建用户失败！'})
    finally:
        cursor.close()
        conn.close()

@app.route('/group/create', methods=['POST'])
def create_group():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': '请先登录！'})
    
    data = request.get_json()
    group_name = data.get('name')
    
    if not group_name:
        return jsonify({'success': False, 'message': '群聊名称不能为空！'})
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # 创建群聊
        cursor.execute('INSERT INTO chat_groups (name, owner_id) VALUES (%s, %s)',
                      (group_name, session['user_id']))
        group_id = cursor.lastrowid
        
        # 将创建者添加为群成员
        cursor.execute('INSERT INTO group_members (group_id, user_id) VALUES (%s, %s)',
                      (group_id, session['user_id']))
        
        conn.commit()
        return jsonify({'success': True, 'group_id': group_id})
    except:
        return jsonify({'success': False, 'message': '创建群聊失败！'})
    finally:
        cursor.close()
        conn.close()

@app.route('/group/<int:group_id>/invite', methods=['POST'])
def invite_to_group(group_id):
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': '请先登录！'})
    
    data = request.get_json()
    user_id = data.get('user_id')
    
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    try:
        # 检查是否是群主或管理员
        cursor.execute('''
            SELECT 1 FROM chat_groups 
            WHERE id = %s AND (owner_id = %s OR %s IN 
                (SELECT user_id FROM users WHERE is_admin = TRUE))
        ''', (group_id, session['user_id'], session['user_id']))
        
        if not cursor.fetchone():
            return jsonify({'success': False, 'message': '无权限邀请！'})
        
        # 检查用户是否已经在群里
        cursor.execute('SELECT 1 FROM group_members WHERE group_id = %s AND user_id = %s',
                      (group_id, user_id))
        if cursor.fetchone():
            return jsonify({'success': False, 'message': '用户已在群聊中！'})
        
        # 创建邀请
        cursor.execute('''
            INSERT INTO group_invites (group_id, inviter_id, invitee_id)
            VALUES (%s, %s, %s)
        ''', (group_id, session['user_id'], user_id))
        
        conn.commit()
        return jsonify({'success': True})
    except:
        return jsonify({'success': False, 'message': '邀请失败！'})
    finally:
        cursor.close()
        conn.close()

@app.route('/group/invite/<int:invite_id>/<string:action>', methods=['POST'])
def handle_group_invite(invite_id, action):
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': '请先登录！'})
    
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    try:
        # 获取邀请信息
        cursor.execute('''
            SELECT * FROM group_invites 
            WHERE id = %s AND invitee_id = %s AND status = 'pending'
        ''', (invite_id, session['user_id']))
        invite = cursor.fetchone()
        
        if not invite:
            return jsonify({'success': False, 'message': '邀请不存在或已处理！'})
        
        if action == 'accept':
            # 添加到群成员
            cursor.execute('''
                INSERT INTO group_members (group_id, user_id)
                VALUES (%s, %s)
            ''', (invite['group_id'], session['user_id']))
            
        # 更新邀请状态
        cursor.execute('''
            UPDATE group_invites 
            SET status = %s 
            WHERE id = %s
        ''', (action, invite_id))
        
        conn.commit()
        return jsonify({'success': True})
    except:
        return jsonify({'success': False, 'message': '处理邀请失败！'})
    finally:
        cursor.close()
        conn.close()

@app.route('/group/<int:group_id>/message', methods=['POST'])
def send_group_message(group_id):
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': '请先登录！'})
    
    data = request.get_json()
    message = data.get('message')
    
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    try:
        # 检查是否是群成员且未被禁言
        cursor.execute('''
            SELECT is_muted FROM group_members 
            WHERE group_id = %s AND user_id = %s
        ''', (group_id, session['user_id']))
        member = cursor.fetchone()
        
        if not member:
            return jsonify({'success': False, 'message': '您不是群成员！'})
        
        if member['is_muted']:
            return jsonify({'success': False, 'message': '您已被禁言！'})
        
        # 发送消息
        cursor.execute('''
            INSERT INTO group_messages (group_id, sender_id, content)
            VALUES (%s, %s, %s)
        ''', (group_id, session['user_id'], message))
        
        conn.commit()
        return jsonify({'success': True})
    except:
        return jsonify({'success': False, 'message': '发送消息失败！'})
    finally:
        cursor.close()
        conn.close()

@app.route('/group/<int:group_id>/kick/<int:user_id>', methods=['POST'])
def kick_member(group_id, user_id):
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': '请先登录！'})
    
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    try:
        # 检查权限
        cursor.execute('''
            SELECT 1 FROM chat_groups 
            WHERE id = %s AND (owner_id = %s OR %s IN 
                (SELECT user_id FROM users WHERE is_admin = TRUE))
        ''', (group_id, session['user_id'], session['user_id']))
        
        if not cursor.fetchone():
            return jsonify({'success': False, 'message': '无权限操作！'})
        
        # 踢出成员
        cursor.execute('DELETE FROM group_members WHERE group_id = %s AND user_id = %s',
                      (group_id, user_id))
        
        conn.commit()
        return jsonify({'success': True})
    except:
        return jsonify({'success': False, 'message': '操作失败！'})
    finally:
        cursor.close()
        conn.close()

@app.route('/group/<int:group_id>/mute/<int:user_id>', methods=['POST'])
def toggle_group_mute(group_id, user_id):
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': '请先登录！'})
    
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    try:
        # 检查权限
        cursor.execute('''
            SELECT 1 FROM chat_groups 
            WHERE id = %s AND (owner_id = %s OR %s IN 
                (SELECT user_id FROM users WHERE is_admin = TRUE))
        ''', (group_id, session['user_id'], session['user_id']))
        
        if not cursor.fetchone():
            return jsonify({'success': False, 'message': '无权限操作！'})
        
        # 更新禁言状态
        cursor.execute('''
            UPDATE group_members 
            SET is_muted = NOT is_muted 
            WHERE group_id = %s AND user_id = %s
        ''', (group_id, user_id))
        
        conn.commit()
        return jsonify({'success': True})
    except:
        return jsonify({'success': False, 'message': '操作失败！'})
    finally:
        cursor.close()
        conn.close()

@app.route('/admin/group/<int:group_id>/owner/<int:new_owner_id>', methods=['POST'])
def change_group_owner(group_id, new_owner_id):
    if not is_admin(session['user_id']):
        return jsonify({'success': False, 'message': '无权限！'})
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute('UPDATE chat_groups SET owner_id = %s WHERE id = %s',
                      (new_owner_id, group_id))
        conn.commit()
        return jsonify({'success': True})
    except:
        return jsonify({'success': False, 'message': '更改群主失败！'})
    finally:
        cursor.close()
        conn.close()

@app.route('/admin/group/create', methods=['POST'])
def admin_create_group():
    if not is_admin(session['user_id']):
        return jsonify({'success': False, 'message': '无权限！'})
    
    data = request.get_json()
    group_name = data.get('name')
    owner_id = data.get('owner_id')
    
    if not group_name or not owner_id:
        return jsonify({'success': False, 'message': '群聊名称和群主不能为空！'})
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # 创建群聊
        cursor.execute('INSERT INTO chat_groups (name, owner_id) VALUES (%s, %s)',
                      (group_name, owner_id))
        group_id = cursor.lastrowid
        
        # 将群主添加为群成员
        cursor.execute('INSERT INTO group_members (group_id, user_id) VALUES (%s, %s)',
                      (group_id, owner_id))
        
        conn.commit()
        return jsonify({'success': True})
    except:
        return jsonify({'success': False, 'message': '创建群聊失败！'})
    finally:
        cursor.close()
        conn.close()

@app.route('/groups')
def group_list():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    # 获取用户加入的群聊
    cursor.execute('''
        SELECT g.*, u.username as owner_name 
        FROM chat_groups g
        JOIN users u ON g.owner_id = u.id
        JOIN group_members gm ON g.id = gm.group_id
        WHERE gm.user_id = %s
    ''', (session['user_id'],))
    groups = cursor.fetchall()
    
    cursor.close()
    conn.close()
    
    return render_template('group_list.html', groups=groups)

@app.route('/group/<int:group_id>')
def group_chat(group_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    # 检查用户是否是群成员
    cursor.execute('''
        SELECT 1 FROM group_members 
        WHERE group_id = %s AND user_id = %s
    ''', (group_id, session['user_id']))
    
    if not cursor.fetchone():
        flash('您不是该群成员！')
        return redirect(url_for('group_list'))
    
    # 获取群信息
    cursor.execute('''
        SELECT g.*, u.username as owner_name 
        FROM chat_groups g
        JOIN users u ON g.owner_id = u.id
        WHERE g.id = %s
    ''', (group_id,))
    group = cursor.fetchone()
    
    # 获取群成员
    cursor.execute('''
        SELECT u.*, gm.is_muted 
        FROM users u
        JOIN group_members gm ON u.id = gm.user_id
        WHERE gm.group_id = %s
    ''', (group_id,))
    members = cursor.fetchall()
    
    # 获取可邀请的用户（不在群中的用户）
    cursor.execute('''
        SELECT u.* FROM users u
        WHERE u.id NOT IN (
            SELECT user_id FROM group_members WHERE group_id = %s
        )
    ''', (group_id,))
    available_users = cursor.fetchall()
    
    # 获取群消息
    cursor.execute('''
        SELECT gm.*, u.username as sender_name 
        FROM group_messages gm
        JOIN users u ON gm.sender_id = u.id
        WHERE gm.group_id = %s
        AND gm.id NOT IN (
            SELECT message_id FROM hidden_group_messages WHERE user_id = %s
        )
        ORDER BY gm.timestamp DESC
    ''', (group_id, session['user_id']))
    messages = cursor.fetchall()
    
    # 检查当前用户是否是群主
    is_owner = group['owner_id'] == session['user_id']
    
    cursor.close()
    conn.close()
    
    return render_template('group_chat.html', 
                         group=group,
                         messages=messages,
                         members=members,
                         available_users=available_users,
                         is_owner=is_owner)

if __name__ == '__main__':
    app.run(debug=True) 