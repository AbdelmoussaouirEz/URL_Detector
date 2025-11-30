# System Architecture

## Overview

The URL Intelligence Extractor follows a **microservices architecture** with clear separation of concerns, enabling maintainability, testability, and scalability.

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Client Application                      │
│              (Browser, CLI, Python Script, etc.)            │
└──────────────────────────┬──────────────────────────────────┘
                           │ HTTP Request (POST /predict)
                           ↓
┌─────────────────────────────────────────────────────────────┐
│                    FastAPI Application                       │
│                        (main.py)                            │
│  ┌────────────────────────────────────────────────────────┐ │
│  │  Request Validation & URL Preprocessing                │ │
│  └────────────────────────────────────────────────────────┘ │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ↓
┌─────────────────────────────────────────────────────────────┐
│                   Service Orchestration                      │
│                                                              │
│  ┌──────────────────┐  ┌──────────────────┐  ┌───────────┐ │
│  │ Feature          │  │ Security         │  │ Scoring   │ │
│  │ Extractor        │  │ Checkers         │  │ System    │ │
│  └──────────────────┘  └──────────────────┘  └───────────┘ │
│           │                      │                   │       │
│           ↓                      ↓                   ↓       │
│  ┌──────────────────────────────────────────────────────┐   │
│  │           Data Aggregation & Analysis                │   │
│  └──────────────────────────────────────────────────────┘   │
3. **SSL Certificate Verification** - 2-3 seconds

### Optimization Strategies

- Run checks in parallel (async)
- Cache results (Redis)

## Testing Architecture

### Unit Tests
- Test each service independently
- Mock external dependencies
- Test edge cases

### Integration Tests
- Test service interactions
- Test API endpoints
- Test error handling

### Coverage Target
- Minimum 80% code coverage
- 100% for critical paths (scoring, ML)

---

**Next**: See [Design Decisions](design-decisions.md) for technical choices and reasoning.