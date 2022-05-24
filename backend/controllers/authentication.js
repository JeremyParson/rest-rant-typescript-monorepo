const router = require("express").Router();
const db = require("../models");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");

const { User } = db;

router.post("/", async (req, res) => {
  let user = await User.findOne({
    where: { email: req.body.email },
  });

  if (
    !user ||
    !(await bcrypt.compare(req.body.password, user.passwordDigest))
  ) {
    res.status(404).json({
      message: `Could not find a user with the provided username and password`,
    });
  } else {
    const result = jwt.sign({ id: user.userId }, process.env.JWT_SECRET);
    res.json({ user: user, token: result });
  }
});

router.get("/profile", async (req, res) => {
  try {
    // Split the authorization header into [ "Bearer", "TOKEN" ]:
    const [authenticationMethod, token] = req.headers.authorization.split(" ");
    console.log(authenticationMethod, token)
    // Only handle "Bearer" authorization for now
    //  (we could add other authorization strategies later):
    if (authenticationMethod == "Bearer") {
      // Decode the JWT
      const result = jwt.verify(token, process.env.JWT_SECRET);
      // Get the logged in user's id from the payload
      const { id } = result;

      // Find the user object using their id:
      let user = await User.findOne({
        where: {
          userId: id,
        },
      });
      res.json(user);
    }
  } catch {
    res.json(null);
  }
});

module.exports = router;
