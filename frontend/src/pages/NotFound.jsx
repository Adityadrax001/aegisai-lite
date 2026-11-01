import { Link } from 'react-router-dom'

export default function NotFound() {
  return (
    <section className="nb-card p-5">
      <h1 className="text-2xl uppercase">Page not found</h1>
      <Link to="/" className="nb-btn mt-4">
        Return to dashboard
      </Link>
    </section>
  )
}