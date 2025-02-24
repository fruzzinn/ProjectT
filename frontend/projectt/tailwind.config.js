/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./app/**/*.{js,ts,jsx,tsx}",
    "./pages/**/*.{js,ts,jsx,tsx}",
    "./components/**/*.{js,ts,jsx,tsx}"
  ],
  theme: {
    extend: {
      colors: {
        "dark-bg": "#121212",  // Dark background
        "dark-cyan": "#00bcd4", // Cyan accent
        "light-text": "#f1f1f1", // Light text
      },
    },
  },
  plugins: [],
};
