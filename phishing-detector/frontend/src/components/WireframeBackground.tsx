function torusPaths(): string[] {
  const major = 2.2
  const minor = 0.95
  const uSteps = 36
  const vSteps = 18
  const rotX = 0
  const rotY = Math.PI / 2
  const camera = 6.4
  const scale = 168
  const cosX = Math.cos(rotX)
  const sinX = Math.sin(rotX)
  const cosY = Math.cos(rotY)
  const sinY = Math.sin(rotY)

  function project(u: number, v: number): [number, number] {
    const x = (major + minor * Math.cos(v)) * Math.cos(u)
    const y = minor * Math.sin(v)
    const z = (major + minor * Math.cos(v)) * Math.sin(u)
    const y1 = y * cosX - z * sinX
    const z1 = y * sinX + z * cosX
    const x2 = x * cosY + z1 * sinY
    const z2 = -x * sinY + z1 * cosY
    const focus = camera / (camera - z2)
    return [x2 * focus * scale, -y1 * focus * scale]
  }

  const paths: string[] = []

  for (let i = 0; i < uSteps; i += 1) {
    const u = (i / uSteps) * Math.PI * 2
    const points: string[] = []
    for (let j = 0; j <= vSteps; j += 1) {
      const [x, y] = project(u, (j / vSteps) * Math.PI * 2)
      points.push(`${j === 0 ? 'M' : 'L'}${x.toFixed(1)} ${y.toFixed(1)}`)
    }
    paths.push(points.join(' '))
  }

  for (let j = 0; j < vSteps; j += 1) {
    const v = (j / vSteps) * Math.PI * 2
    const points: string[] = []
    for (let i = 0; i <= uSteps; i += 1) {
      const [x, y] = project((i / uSteps) * Math.PI * 2, v)
      points.push(`${i === 0 ? 'M' : 'L'}${x.toFixed(1)} ${y.toFixed(1)}`)
    }
    paths.push(points.join(' '))
  }

  return paths
}

const PATHS = torusPaths()

export default function WireframeBackground() {
  return (
    <div className="wireframe" aria-hidden="true">
      <svg className="wireframe-svg" viewBox="-520 -240 1040 480" preserveAspectRatio="xMidYMid meet">
        {PATHS.map((d, index) => (
          <path key={index} d={d} />
        ))}
      </svg>
    </div>
  )
}
