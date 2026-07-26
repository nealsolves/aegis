import { ChevronDown, ExternalLink } from 'lucide-react'
import {
  bedrockVerificationCopy,
  faqCategories,
  faqPageCopy,
  type FaqBlock,
} from '@/content/faqContent'
import { useDemoService } from '@/context/DemoServiceContext'

function renderBlock(block: FaqBlock, itemId: string, index: number) {
  if (block.type === 'list') {
    return (
      <ul key={`${itemId}-block-${index}`}>
        {block.items.map(item => <li key={item}>{item}</li>)}
      </ul>
    )
  }

  return <p key={`${itemId}-block-${index}`}>{block.text}</p>
}

export default function FaqPage() {
  const { manifest, status } = useDemoService()
  const hasVerifiedBedrock = (
    status === 'ready'
    && manifest?.adapters.includes('bedrock') === true
  )
  const bedrockStatus = status === 'ready'
    ? {
        tone: hasVerifiedBedrock ? 'verified' : 'not-published',
        text: hasVerifiedBedrock
          ? bedrockVerificationCopy.verified
          : bedrockVerificationCopy.notPublished,
      }
    : {
        tone: 'neutral',
        text: bedrockVerificationCopy.unavailable,
      }

  return (
    <main className="faq-page">
      <header className="faq-hero">
        <p className="scenario-kicker">{faqPageCopy.eyebrow}</p>
        <h1>{faqPageCopy.title}</h1>
        <p>{faqPageCopy.description}</p>
      </header>

      <div className="faq-categories">
        {faqCategories.map(category => (
          <section
            className="faq-category"
            aria-labelledby={`faq-category-${category.id}`}
            key={category.id}
          >
            <div className="faq-category__heading">
              <h2 id={`faq-category-${category.id}`}>{category.title}</h2>
              <p>{category.description}</p>
            </div>

            <div className="faq-category__items">
              {category.items.map(item => (
                <details className="faq-item" key={item.id}>
                  <summary>
                    <span>{item.question}</span>
                    <ChevronDown aria-hidden="true" />
                  </summary>

                  <div className="faq-answer">
                    {item.answer.map((block, index) => (
                      renderBlock(block, item.id, index)
                    ))}

                    {item.requiresAdapter === 'bedrock' && (
                      <div
                        className={`faq-adapter-status faq-adapter-status--${bedrockStatus.tone}`}
                        role="status"
                        aria-live="polite"
                        aria-atomic="true"
                      >
                        <span>{faqPageCopy.verificationLabel}</span>
                        <p>{bedrockStatus.text}</p>
                      </div>
                    )}

                    {item.sources && item.sources.length > 0 && (
                      <div className="faq-sources">
                        <span>{faqPageCopy.sourcesLabel}</span>
                        <ul>
                          {item.sources.map(source => (
                            <li key={source.href}>
                              <a
                                href={source.href}
                                target="_blank"
                                rel="noopener noreferrer"
                              >
                                {source.label}
                                <ExternalLink aria-hidden="true" />
                              </a>
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>
                </details>
              ))}
            </div>
          </section>
        ))}
      </div>
    </main>
  )
}
