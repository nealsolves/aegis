import { useCallback, useState } from 'react'
import { HashRouter, Navigate, Route, Routes, useLocation } from 'react-router-dom'
import HelpButton from '@/components/HelpButton'
import HelpDrawer from '@/components/HelpDrawer'
import AppNav from '@/components/layout/AppNav'
import DemoNav from '@/components/layout/DemoNav'
import LabHero from '@/components/layout/LabHero'
import LabTabs from '@/components/layout/LabTabs'
import { DemoServiceNotice } from '@/components/service/DemoServiceNotice'
import { labRoutesCopy, placeholderCopy } from '@/content/demoCopy'
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
import ArchitecturePage from '@/pages/ArchitecturePage'
import IntroductionPage from '@/pages/IntroductionPage'
import ScenariosIndexPage from '@/pages/ScenariosIndexPage'
import ScenarioPage from '@/routes/scenarios/ScenarioPage'

const LABS = labRoutesCopy

interface RouteDescriptor {
  helpLabId: number | null
  showDemoNav: boolean
  showDemoService: boolean
  showLabTabs: boolean
}

function describeRoute(pathname: string): RouteDescriptor {
  const labMatch = pathname.match(/^\/lab\/(\d+)$/)
  const labId = labMatch ? Number.parseInt(labMatch[1], 10) : null
  const knownLabId = labId !== null && LABS.some((lab) => lab.num === labId)
    ? labId
    : null
  const isDemoRoute = pathname.startsWith('/demo/')
  const isLabRoute = pathname.startsWith('/lab/')

  return {
    helpLabId: pathname === '/demo/architecture' ? 0 : knownLabId,
    showDemoNav: isDemoRoute || isLabRoute || pathname === '/faq',
    showDemoService: isDemoRoute || isLabRoute,
    showLabTabs: knownLabId !== null,
  }
}

function AppContent() {
  const location = useLocation()
  const [isHelpOpen, setIsHelpOpen] = useState(false)
  const route = describeRoute(location.pathname)

  const handleOpen = useCallback(() => setIsHelpOpen(true), [])
  const handleClose = useCallback(() => setIsHelpOpen(false), [])

  return (
    <div className="app-shell">
      <AppNav />
      {route.showDemoNav && <DemoNav />}
      {route.showDemoService && <DemoServiceNotice />}
      {route.showLabTabs && <LabTabs labs={LABS} />}
      <Routes>
        <Route path="/" element={<IntroductionPage />} />
        <Route path="/architecture" element={<Navigate to="/demo/architecture" replace />} />
        <Route path="/demo/architecture" element={<ArchitecturePage />} />
        <Route path="/demo/scenarios" element={<ScenariosIndexPage />} />
        <Route path="/demo/scenarios/:scenarioId" element={<ScenarioPage />} />
        <Route
          path="/demo/labs"
          element={<PlaceholderPage copy={placeholderCopy.labs} />}
        />
        <Route path="/faq" element={<PlaceholderPage copy={placeholderCopy.faq} />} />
        <Route path="/lab/1" element={<><LabHero labNum={1} title={LABS[0].heroTitle} /><Lab1RiskScoring /></>} />
        <Route path="/lab/2" element={<><LabHero labNum={2} title={LABS[1].heroTitle} /><Lab2Signing /></>} />
        <Route path="/lab/3" element={<><LabHero labNum={3} title={LABS[2].heroTitle} /><Lab3AuditChain /></>} />
        <Route path="/lab/4" element={<><LabHero labNum={4} title={LABS[3].heroTitle} /><Lab4Composition /></>} />
        <Route path="/lab/5" element={<><LabHero labNum={5} title={LABS[4].heroTitle} /><Lab5Loaders /></>} />
        <Route path="/lab/6" element={<><LabHero labNum={6} title={LABS[5].heroTitle} /><Lab6CustomGates /></>} />
        <Route path="/lab/7" element={<><LabHero labNum={7} title={LABS[6].heroTitle} /><Lab7Compliance /></>} />
        <Route path="/lab/8" element={<><LabHero labNum={8} title={LABS[7].heroTitle} /><Lab8GovernedKnowledgeBase /></>} />
        <Route path="/lab/9" element={<><LabHero labNum={9} title={LABS[8].heroTitle} /><Lab9GovernedVsUngoverned /></>} />
        <Route path="/lab/10" element={<><LabHero labNum={10} title={LABS[9].heroTitle} /><Lab10SplitEnforcementExplorer /></>} />
        <Route path="/lab/11" element={<><LabHero labNum={11} title={LABS[10].heroTitle} /><Lab11WorkflowLab /></>} />
      </Routes>
      {route.helpLabId !== null && (
        <>
          <HelpButton isOpen={isHelpOpen} onOpen={handleOpen} />
          <HelpDrawer
            labId={route.helpLabId}
            isOpen={isHelpOpen}
            onClose={handleClose}
          />
        </>
      )}
    </div>
  )
}

function PlaceholderPage({
  copy,
}: {
  copy: {
    eyebrow: string
    title: string
    description: string
  }
}) {
  return (
    <main className="placeholder-page">
      <p className="intro-eyebrow">{copy.eyebrow}</p>
      <h1>{copy.title}</h1>
      <p>{copy.description}</p>
    </main>
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
