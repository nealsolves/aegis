import { useCallback, useState } from 'react'
import { HashRouter, Navigate, Route, Routes, useLocation } from 'react-router-dom'
import HelpButton from '@/components/HelpButton'
import HelpDrawer, {
  type ResultHelpContext,
} from '@/components/HelpDrawer'
import LabRouteLayout from '@/components/layout/LabRouteLayout'
import SiteHeader from '@/components/layout/SiteHeader'
import { DemoServiceNotice } from '@/components/service/DemoServiceNotice'
import { LABS, LABS_BY_ID } from '@/content/labCatalog'
import Lab1RiskScoring from '@/labs/Lab1RiskScoring'
import Lab2Signing from '@/labs/Lab2Signing'
import Lab3AuditChain from '@/labs/Lab3AuditChain'
import Lab4Composition from '@/labs/Lab4Composition'
import Lab5Loaders from '@/labs/Lab5Loaders'
import Lab6CustomGates from '@/labs/Lab6CustomGates'
import Lab7Compliance from '@/labs/Lab7Compliance'
import Lab8GovernedKnowledgeBase from '@/labs/Lab8GovernedKnowledgeBase'
import Lab9GovernedVsUngoverned from '@/labs/Lab9GovernedVsUngoverned'
import Lab10SplitEnforcementExplorer from '@/labs/Lab10SplitEnforcementExplorer'
import Lab11WorkflowLab from '@/labs/Lab11WorkflowLab'
import Lab12IntegrationAdapters from '@/labs/Lab12IntegrationAdapters'
import ArchitecturePage from '@/pages/ArchitecturePage'
import FaqPage from '@/pages/FaqPage'
import IntroductionPage from '@/pages/IntroductionPage'
import LabsIndexPage from '@/pages/LabsIndexPage'
import ScenariosIndexPage from '@/pages/ScenariosIndexPage'
import ScenarioPage from '@/routes/scenarios/ScenarioPage'

interface RouteDescriptor {
  helpLabId: number | null
  showDemoNav: boolean
  showDemoService: boolean
  isDemoContext: boolean
}

function describeRoute(pathname: string): RouteDescriptor {
  const normalizedPathname = (pathname.replace(/\/+$/, '') || '/').toLowerCase()
  const knownLab = LABS.find(lab => lab.path === normalizedPathname)
  const isDemoRoute = normalizedPathname.startsWith('/demo/')
  const isLabRoute = normalizedPathname.startsWith('/lab/')

  return {
    helpLabId: normalizedPathname === '/demo/architecture' ? 0 : knownLab?.id ?? null,
    showDemoNav: isDemoRoute || isLabRoute || normalizedPathname === '/faq',
    showDemoService: isDemoRoute || isLabRoute,
    isDemoContext: isDemoRoute || isLabRoute,
  }
}

function AppContent() {
  const location = useLocation()
  const [isHelpOpen, setIsHelpOpen] = useState(false)
  const [resultHelpState, setResultHelpState] = useState<{
    locationKey: string
    context: ResultHelpContext | null
  } | null>(null)
  const route = describeRoute(location.pathname)

  const handleOpen = useCallback(() => setIsHelpOpen(true), [])
  const handleClose = useCallback(() => setIsHelpOpen(false), [])
  const handleResultHelpContext = useCallback(
    (context: ResultHelpContext | null) => {
      setResultHelpState({
        locationKey: location.key,
        context,
      })
    },
    [location.key],
  )
  const labRoutes = [
    { lab: LABS_BY_ID[1], body: <Lab1RiskScoring /> },
    { lab: LABS_BY_ID[2], body: <Lab2Signing /> },
    { lab: LABS_BY_ID[3], body: <Lab3AuditChain /> },
    { lab: LABS_BY_ID[4], body: <Lab4Composition /> },
    { lab: LABS_BY_ID[5], body: <Lab5Loaders /> },
    { lab: LABS_BY_ID[6], body: <Lab6CustomGates /> },
    { lab: LABS_BY_ID[7], body: <Lab7Compliance /> },
    { lab: LABS_BY_ID[8], body: <Lab8GovernedKnowledgeBase /> },
    { lab: LABS_BY_ID[9], body: <Lab9GovernedVsUngoverned /> },
    { lab: LABS_BY_ID[10], body: <Lab10SplitEnforcementExplorer /> },
    { lab: LABS_BY_ID[11], body: <Lab11WorkflowLab /> },
    {
      lab: LABS_BY_ID[12],
      body: (
        <Lab12IntegrationAdapters
          onResultHelpContext={handleResultHelpContext}
        />
      ),
    },
  ] as const
  const resultHelpContext = (
    route.helpLabId === 12
    && resultHelpState?.locationKey === location.key
  )
    ? resultHelpState.context ?? undefined
    : undefined

  return (
    <div className="app-shell">
      <SiteHeader
        showDemoNav={route.showDemoNav}
        isDemoContext={route.isDemoContext}
      />
      {route.showDemoService && <DemoServiceNotice />}
      {route.helpLabId !== null && (
        <div className="help-launcher">
          <HelpButton isOpen={isHelpOpen} onOpen={handleOpen} />
        </div>
      )}
      <Routes>
        <Route path="/" element={<IntroductionPage />} />
        <Route path="/architecture" element={<Navigate to="/demo/architecture" replace />} />
        <Route path="/demo/architecture" element={<ArchitecturePage />} />
        <Route path="/demo/scenarios" element={<ScenariosIndexPage />} />
        <Route path="/demo/scenarios/:scenarioId" element={<ScenarioPage />} />
        <Route
          path="/demo/labs"
          element={<LabsIndexPage />}
        />
        <Route path="/faq" element={<FaqPage />} />
        {labRoutes.map(({ lab, body }) => (
          <Route
            path={lab.path}
            element={<LabRouteLayout lab={lab}>{body}</LabRouteLayout>}
            key={lab.id}
          />
        ))}
      </Routes>
      {route.helpLabId !== null && (
        <HelpDrawer
          labId={route.helpLabId}
          isOpen={isHelpOpen}
          onClose={handleClose}
          resultContext={resultHelpContext}
        />
      )}
    </div>
  )
}

export default function App() {
  return (
    <HashRouter>
      <AppContent />
    </HashRouter>
  )
}

export { LABS }
