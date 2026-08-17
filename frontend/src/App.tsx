import { Gallery } from './gallery/Gallery';

/**
 * P20 is the component system, so the app *is* the gallery.
 *
 * No router yet, deliberately: there is one surface, and a routing library added before there
 * is anything to route between is a dependency chosen for a problem nobody has (AGENTS.md
 * §4.11). P21 adds the real surfaces and the routing that connects them.
 */
export function App() {
  return <Gallery />;
}
