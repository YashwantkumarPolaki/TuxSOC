import { useState, useEffect, useRef } from 'react'

export function useCountUp(target: number, duration = 1200): number {
  const [current, setCurrent] = useState(0)
  const startRef = useRef<number | null>(null)
  const rafRef = useRef<number | null>(null)
  const prevTarget = useRef(0)

  useEffect(() => {
    const startValue = prevTarget.current
    prevTarget.current = target
    startRef.current = null

    const easeOut = (t: number) => 1 - Math.pow(1 - t, 3)

    const animate = (timestamp: number) => {
      if (startRef.current === null) startRef.current = timestamp
      const elapsed = timestamp - startRef.current
      const progress = Math.min(elapsed / duration, 1)
      const easedProgress = easeOut(progress)
      setCurrent(Math.round(startValue + (target - startValue) * easedProgress))
      if (progress < 1) {
        rafRef.current = requestAnimationFrame(animate)
      }
    }

    rafRef.current = requestAnimationFrame(animate)
    return () => {
      if (rafRef.current) cancelAnimationFrame(rafRef.current)
    }
  }, [target, duration])

  return current
}
