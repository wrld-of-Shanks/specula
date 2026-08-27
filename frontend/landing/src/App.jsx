import Nav from './components/Nav';
import Hero from './components/Hero';
import CTA from './components/CTA';
import Footer from './components/Footer';

export default function App() {
  return (
    <>
      <div className="scanlines" />
      <Nav />
      <main>
        <Hero />
        <CTA />
      </main>
      <Footer />
    </>
  );
}
