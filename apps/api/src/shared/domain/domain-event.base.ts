/**
 * Domain Event interface.
 * Captured within aggregates and dispatched upon transaction commit.
 */
export interface IDomainEvent {
  dateTimeOccurred: Date;
  aggregateId: string;
}
