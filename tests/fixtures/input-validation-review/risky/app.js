const { exec } = require("child_process");
app.get("/search", (req, res) => {
  db.query(`SELECT * FROM items WHERE name = '${req.query.q}'`);
  exec(`convert ${req.query.file} out.png`);
  res.sendFile(req.query.path);
  fetch(req.query.url);
  res.redirect(req.query.next);
});
el.innerHTML = location.hash;
const html = <div dangerouslySetInnerHTML={{ __html: comment }} />;
eval(userCode);
// el.innerHTML = "commented out";
