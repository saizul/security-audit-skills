const { execFile } = require("child_process");
app.get("/search", async (req, res) => {
  await db.query("SELECT * FROM items WHERE name = $1", [req.query.q]);
  execFile("convert", [name, "out.png"]);
  el.textContent = req.query.q;
});
