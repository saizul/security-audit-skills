class UserDao {
  User find(String name) throws Exception {
    ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE name = '" + name + "'");
    ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
    Runtime.getRuntime().exec(cmd);
    return null;
  }
}
