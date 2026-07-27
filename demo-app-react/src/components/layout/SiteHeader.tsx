import AppNav from '@/components/layout/AppNav'
import DemoNav from '@/components/layout/DemoNav'
import { publicNavCopy } from '@/content/demoCopy'

interface SiteHeaderProps {
  showDemoNav: boolean
  isDemoContext: boolean
  emphasizeDemoLink: boolean
}

export default function SiteHeader({
  showDemoNav,
  isDemoContext,
  emphasizeDemoLink,
}: SiteHeaderProps) {
  return (
    <header className="site-header">
      <AppNav
        isDemoContext={isDemoContext}
        emphasizeDemoLink={emphasizeDemoLink}
      />
      {showDemoNav ? (
        <DemoNav />
      ) : (
        <div className="site-header__row site-header__context">
          <div className="site-header__context-inner">
            {publicNavCopy.descriptor}
          </div>
        </div>
      )}
    </header>
  )
}
