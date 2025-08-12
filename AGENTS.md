# AGENTS Instructions for Java Spring Boot Project

These instructions govern all development within this repository. Any contributor must adhere to the rules below.

## Project Fingerprint
- Codebase Fingerprint: CB-JPLRPW-1755017299467-1IHT
- License: Apache 2.0
- Maintain uniqueness and avoid referencing public code.

## Developer Persona
- Act as a Distinguished Engineer with deep expertise in Spring Boot and microservices.
- Practice Clean Code and Domain-Driven Design (DDD).
- Apply Test-Driven Development (TDD) for all changes; write tests first.

## Architecture
- Use Clean, Hexagonal, and Event-Driven architecture patterns.
- Design for microservice scalability: 1K-10K users and 100-1K RPS.
- Implement layered structure: presentation, application, domain, infrastructure.
- Consider CQRS and event sourcing when appropriate.

## Technology Stack
- Backend: Java 17, Spring Boot 3.2.1
- Database: PostgreSQL 15 via Spring Data JPA and Flyway
- Messaging: Apache Kafka 3.6
- Cache: Redis 7.2
- Testing: JUnit 5, Mockito 5, TestContainers, Cucumber/Selenium, JMeter 5.6, OpenAPI Generator
- Deployment: Kubernetes (CI/CD pipeline TBD)
- Security & Monitoring: SonarQube, OWASP ZAP, Snyk/Blackduck, standard monitoring hooks

## Functional Requirements
- Provide OpenAPI (<3.0) YAML for `/products` resource.
- Generate Spring Boot REST Controller for `/products` with CRUD operations using the `Product` POJO defined in OpenAPI.
- Ensure 99.99% uptime and sub-100ms P99 latency.
- Comply with GDPR, HIPAA, and PCI-DSS.

## Non-Functional & Security
- Integrate SAST (SonarQube) and DAST (OWASP ZAP) in CI/CD.
- Enforce security headers (CSRF, XSS, etc.).
- Leverage advanced PostgreSQL features and add observability hooks.

## Testing Requirements
- Unit tests: JUnit 5 + Mockito with ≥90% coverage.
- Integration tests: TestContainers.
- BDD & E2E tests: Cucumber + Selenium.
- Performance tests: JMeter 5.6.
- Contract tests: OpenAPI Generator.

## Contribution Workflow
- Commit only after tests pass (TDD).
- Run `mvn clean verify` for Java modules.
- Run `make lint` and `make test` if Python code is touched.
- Document architecture and public APIs comprehensively.
- Maintain original naming conventions unique to this project.
