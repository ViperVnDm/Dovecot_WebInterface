// Builds app/static/css/app.css, which replaces the runtime Tailwind CDN
// script (that needed a third-party script origin in the CSP). Rebuild after
// adding new utility classes to templates:
//
//   npx tailwindcss@3.4.19 -c tailwind/tailwind.config.js \
//       -i tailwind/input.css -o app/static/css/app.css --minify
//
// Class names must appear literally in the scanned files — don't build them
// by string concatenation.
module.exports = {
  content: ["./app/templates/**/*.html", "./app/**/*.py"],
  theme: { extend: {} },
  plugins: [],
};
