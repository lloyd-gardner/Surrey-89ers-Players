/* Web app manifest, one per player.
   A phone reads this when a player adds their portal to the home
   screen. It is what makes the icon open as an app (which iPhones
   require before they allow notifications) and makes it open on
   that player's own page rather than the site's front page. */
module.exports = function handler(req, res){
  const raw  = String((req.query && req.query.p) || "").toLowerCase();
  const slug = /^[a-z0-9-]{1,60}$/.test(raw) ? raw : "";
  res.setHeader("Content-Type", "application/manifest+json; charset=utf-8");
  res.setHeader("Cache-Control", "public, max-age=0, must-revalidate");
  res.status(200).send(JSON.stringify({
    name: "Surrey 89ers Player Portal",
    short_name: "89ers",
    id: "/" + slug,
    start_url: "/" + slug,
    scope: "/",
    display: "standalone",
    background_color: "#080f0b",
    theme_color: "#080f0b",
    icons: [
      { src: "/icons/icon-192.png", sizes: "192x192", type: "image/png" },
      { src: "/icons/icon-512.png", sizes: "512x512", type: "image/png" }
    ]
  }));
};
