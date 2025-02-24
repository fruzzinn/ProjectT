/** @type {import('postcss-load-config').Config} */
const config = {
  plugins: {
    tailwindcss: {},
  },
};

export default config;

/** @type {import('tailwindcss').Config} */
export default {
  plugins: {
    '@tailwindcss/postcss': {},
  },
}