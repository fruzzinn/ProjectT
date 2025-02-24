export default function Footer() {
  return (
    <footer className="text-center p-4 mt-6 bg-gray-200">
      © {new Date().getFullYear()} Cyber Threat Dashboard
    </footer>
  );
}